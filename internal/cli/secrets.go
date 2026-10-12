package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	// minPassphraseLength is the floor for a key export passphrase (spec §10).
	minPassphraseLength = 12
	maxPassphraseBytes  = 1024
	// maxSecretValueBytes is the server's bound for one imported value; asking
	// here saves a round trip.
	maxSecretValueBytes = 64 << 10
)

func newSecretsCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Import secrets and manage the master keys",
		Long: "Secret values and passphrases are read from the terminal (no echo) or from standard input, never from\n" +
			"an argument or an environment variable. Every online operation is the high-risk secret.write action:\n" +
			"policy usually parks it as a job waiting for approval.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newSecretsImportCmd(env), newRotateMasterKeyCmd(env), newRetireKeyCmd(env),
		newExportKeyCmd(env), newImportKeyCmd(env), newKeysListCmd(env),
	)
	return cmd
}

// ---- secrets import ---------------------------------------------------------------

func newSecretsImportCmd(env []string) *cobra.Command {
	var name, fromFile string
	var offline, deleteSource bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Store a secret value as the next version of a named secret",
		Long: "Store a secret value, read from the terminal (no echo), from standard input or from a file with --from-file\n" +
			"(which must not be readable by others). The value is sealed on the server and never shown again.\n\n" +
			"With --offline (for a value the server needs before any administrator exists, such as the OIDC client\n" +
			"secret or a provider token) nothing is requested: the service must be stopped, and the value is sealed with\n" +
			"the active master key straight into the database. With --from-file, --delete-source unlinks the file once\n" +
			"the value is committed, and only then.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return usageErrorf("--name is required")
			}
			if deleteSource && (!offline || fromFile == "") {
				return usageErrorf("--delete-source needs --offline and --from-file")
			}
			if offline {
				return importSecretOffline(cmd, env, name, fromFile, deleteSource)
			}
			value, err := secretValue(cmd, fromFile)
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			direct, err := api.ImportSecret(cmd.Context(), wire.ImportSecretRequest{Name: name, Value: value})
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(v wire.SecretVersion) string {
				return fmt.Sprintf("stored %s version %d", v.Name, v.Version)
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "secret name, e.g. providers/pve/token")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from this file (mode 0600) instead of the terminal or stdin")
	cmd.Flags().BoolVar(&offline, "offline", false, "store the value with the service stopped, without an administrator")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "with --offline --from-file: delete the file once the value is committed")
	return cmd
}

// ---- secrets import --offline ---------------------------------------------------------

const eventSecretImported = "secret.imported"

func importSecretOffline(cmd *cobra.Command, env []string, name, fromFile string, deleteSource bool) error {
	if name == secrets.SSHIdentityName {
		return usageErrorf("secret %s is the instance SSH identity: it is never imported", name)
	}
	var source secretFile
	var value string
	var err error
	if fromFile != "" {
		source, err = readSecretFile(fromFile)
		value = source.value
		defer source.close()
	} else {
		value, err = secretValue(cmd, "")
	}
	if err != nil {
		return err
	}
	session, err := openOffline(cmd, env)
	if err != nil {
		return err
	}
	defer session.close()
	db, err := session.writableDatabase(cmd.Context())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	ref, err := storeOffline(cmd.Context(), db, session.keysDir, name, value)
	if err != nil {
		return err
	}
	if deleteSource {
		if err := source.remove(); err != nil {
			return fmt.Errorf("stored %s version %d but could not delete %s: %w", ref.Name, ref.Version, fromFile, err)
		}
	}
	return emit(cmd, wire.SecretVersion{Name: ref.Name, Version: ref.Version}, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "stored %s version %d\n", ref.Name, ref.Version)
		return err
	})
}

// storeOffline seals value with the active master key as the next version of
// name and records who did it: the system actor, and the uid of the person
// running this command (there is no peer to verify).
func storeOffline(ctx context.Context, db *database.DB, keysDir, name, value string) (secrets.Ref, error) {
	clock, ids := domain.SystemClock{}, domain.UUIDv7Generator{}
	repo := offlineSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: db.Reader()}, db: db}
	keys, err := secrets.OpenFileKeys(ctx, keysDir, repo, ids)
	if err != nil {
		return secrets.Ref{}, err
	}
	ref, err := secrets.NewStore(keys, repo, ids, clock).Put(ctx, name, audit.Secret(value), map[string]any{"source": "import"})
	if err != nil {
		return secrets.Ref{}, err
	}
	emitter := audit.Emitter{Clock: clock, IDs: ids, Source: "offline_cli"}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := emitter.Emit(ctx, database.EventsIn(tx), domain.Event{
			ActorType: domain.ActorSystem, Action: eventSecretImported, ResourceType: domain.ResourceSecret,
			Severity: domain.SeverityInfo, Result: domain.ResultSucceeded,
			Data: map[string]any{"name": ref.Name, "version": ref.Version, "peer_uid": os.Getuid(), "via": "offline"},
		})
		return err
	})
	if err != nil {
		return secrets.Ref{}, fmt.Errorf("the secret was stored but its audit event was not: %w", err)
	}
	return ref, nil
}

func secretValue(cmd *cobra.Command, fromFile string) (string, error) {
	if fromFile == "" {
		return readSecret(cmd, secretInput{prompt: "Secret value: ", whole: true, limit: maxSecretValueBytes})
	}
	source, err := readSecretFile(fromFile)
	source.close()
	return source.value, err
}

// secretFile is a --from-file source that was opened without following links
// and judged through the open descriptor, so the file that was checked is the
// file that was read. The descriptor stays open until close, so the inode
// cannot be freed and handed to a file swapped in at the same path.
type secretFile struct {
	path   string
	file   *os.File
	opened fs.FileInfo
	value  string
}

func (s secretFile) close() {
	if s.file != nil {
		_ = s.file.Close()
	}
}

func readSecretFile(path string) (secretFile, error) {
	// O_NONBLOCK keeps a FIFO from hanging the open before it can be refused.
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, syscall.ELOOP):
		return secretFile{}, usageErrorf("%s is a symbolic link: name the file itself", path)
	case err != nil:
		return secretFile{}, usageErrorf("cannot read %s: %v", path, err)
	}
	fail := func(err error) (secretFile, error) {
		_ = f.Close()
		return secretFile{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return fail(usageErrorf("cannot read %s: %v", path, err))
	}
	if err := checkSecretFile(path, info, os.Geteuid()); err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretValueBytes+3))
	if err != nil {
		return fail(usageErrorf("cannot read %s: %v", path, err))
	}
	value, err := checkSecret(trimFinalNewline(string(data)), maxSecretValueBytes)
	if err != nil {
		return fail(err)
	}
	return secretFile{path: path, file: f, opened: info, value: value}, nil
}

func checkSecretFile(path string, info fs.FileInfo, euid int) error {
	switch {
	case !info.Mode().IsRegular():
		return usageErrorf("%s is not a regular file", path)
	case info.Mode().Perm()&0o077 != 0:
		return usageErrorf("%s is readable by others (mode %04o): chmod 600 it first", path, info.Mode().Perm())
	case fileOwner(info) != euid:
		return usageErrorf("%s is not owned by you (uid %d)", path, euid)
	}
	return nil
}

func fileOwner(info fs.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}

// remove unlinks the file only while its directory entry still names the file
// that was read: a path swapped for another file or a link is left alone.
func (s secretFile) remove() error {
	current, err := os.Lstat(s.path)
	if err != nil {
		return err
	}
	if !os.SameFile(s.opened, current) {
		return errors.New("the path no longer names the file that was read")
	}
	return os.Remove(s.path)
}

func trimFinalNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
		if len(s) > 0 && s[len(s)-1] == '\r' {
			s = s[:len(s)-1]
		}
	}
	return s
}

// offlineSecrets is the secrets.Repo of an offline import: it reads like the
// read-only repository and writes only new versions. The database lock makes
// the version the store computed the one the insert assigns.
type offlineSecrets struct {
	database.ReadOnlySecrets
	db *database.DB
}

func (r offlineSecrets) Get(ctx context.Context, name string, version int) (secrets.Record, error) {
	stored, err := database.GetSecret(ctx, r.db.Reader(), name, version)
	if err != nil {
		return secrets.Record{}, err
	}
	metadata, err := json.Marshal(stored.Metadata)
	if err != nil {
		return secrets.Record{}, fmt.Errorf("encode secret metadata: %w", err)
	}
	return secrets.Record{
		ID: stored.ID, Name: stored.Name, Version: stored.Version, EnvelopeVersion: stored.EnvelopeVersion, KEKID: stored.KEKID,
		WrappedDEK: stored.WrappedDEK, Ciphertext: stored.Ciphertext, MetadataJSON: string(metadata), CreatedAt: stored.CreatedAt,
	}, nil
}

func (r offlineSecrets) Put(ctx context.Context, rec secrets.Record) error {
	var metadata map[string]any
	if err := json.Unmarshal([]byte(rec.MetadataJSON), &metadata); err != nil {
		return fmt.Errorf("decode secret metadata: %w", err)
	}
	return r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutSecretVersion(ctx, tx, database.SecretRecord{
			ID: rec.ID, Name: rec.Name, EnvelopeVersion: rec.EnvelopeVersion, KEKID: rec.KEKID,
			WrappedDEK: rec.WrappedDEK, Ciphertext: rec.Ciphertext, Metadata: metadata, CreatedAt: rec.CreatedAt,
		})
		return err
	})
}

// ---- keys -------------------------------------------------------------------------------

func newKeysListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "List the master key ids (never the keys)",
		Long:  "List the master keys the server knows: the ids to give to export-key and retire-key, which one is active,\nand whether the daemon holds each. Key material is never shown.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListMasterKeys(cmd.Context())
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeMasterKeys(w, page.Items) })
		},
	}
}

func writeMasterKeys(w io.Writer, keys []wire.MasterKey) error {
	rows := make([][]string, len(keys))
	for i, k := range keys {
		rows[i] = []string{string(k.ID), yesNo(k.Active), yesNo(k.Loaded), formatTime(k.CreatedAt)}
	}
	return table(w, []string{"ID", "ACTIVE", "LOADED", "CREATED"}, rows)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- rotate and retire ---------------------------------------------------------------

func newRotateMasterKeyCmd(env []string) *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "rotate-master-key",
		Short: "Create a new master key and rewrap every secret under it",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := confirm(cmd, "Rotate the master key?", assumeYes); err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			direct, err := api.RotateMasterKey(cmd.Context())
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(r wire.MasterKeyRotated) string {
				return fmt.Sprintf("master key %s is active (replaces %s); %d secret(s) rewrapped", r.ActiveKEKID, r.PreviousKEKID, r.Rewrapped)
			})
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newRetireKeyCmd(env []string) *cobra.Command {
	var handled, assumeYes bool
	cmd := &cobra.Command{
		Use:   "retire-key <kek-id>",
		Short: "Delete an old master key that nothing references any more",
		Long: "Delete an old master key file. It refuses while a secret, a backup archive or a running backup still uses it.\n" +
			"Backups copied elsewhere are unknown to SuperMgmt: --external-backups-handled records that you re-made or\n" +
			"discarded them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if !handled {
				return usageErrorf("retiring a key needs --external-backups-handled: backups copied elsewhere may still need it")
			}
			if err := confirm(cmd, fmt.Sprintf("Retire master key %s? Archives that need it become unrestorable.", id), assumeYes); err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			direct, err := api.RetireMasterKey(cmd.Context(), wire.RetireKeyRequest{KEKID: id, ExternalBackupsHandled: true})
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(struct{}) string { return fmt.Sprintf("retired master key %s", id) })
		},
	}
	cmd.Flags().BoolVar(&handled, "external-backups-handled", false, "acknowledge that copies of backups kept elsewhere were re-made or discarded")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}

// ---- export-key ------------------------------------------------------------------------

type exportFlags struct {
	out     string
	execute bool
	offline bool
}

func newExportKeyCmd(env []string) *cobra.Command {
	var f exportFlags
	cmd := &cobra.Command{
		Use:   "export-key <kek-id>",
		Short: "Back up a master key as a passphrase-protected file",
		Long: "Export a master key (SMKEY1) wrapped under a passphrase of at least 12 characters, read from the terminal\n" +
			"or standard input. Without --execute this only requests the export: policy parks it as a job that exports\n" +
			"nothing. After it is approved, run the command again with --execute to receive the file, once, within 24h.\n" +
			"If policy needs no approval, --execute exports at once. The export is served on the local-mode socket only.\n\n" +
			"With --offline (the way on a server) nothing is requested: the service must be stopped, and the key file is\n" +
			"read directly under the database lock.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if f.offline {
				return exportKeyOffline(cmd, env, id, f)
			}
			return exportKeyOnline(cmd, env, id, f)
		},
	}
	cmd.Flags().StringVar(&f.out, "out", "", "write the export to this new file (mode 0600); default: stdout, if it is not a terminal")
	cmd.Flags().BoolVar(&f.execute, "execute", false, "execute an approved export request (asks for the passphrase)")
	cmd.Flags().BoolVar(&f.offline, "offline", false, "export from the key directory with the service stopped")
	return cmd
}

func exportKeyOnline(cmd *cobra.Command, env []string, id domain.ID, f exportFlags) error {
	where, err := resolveTarget(cmd, env)
	if err != nil {
		return err
	}
	if where.remote != nil {
		return usageErrorf("export-key is never served over HTTPS: on a server stop the service and use --offline")
	}
	req := wire.ExportKeyRequest{KEKID: id}
	var sink *exportSink
	if f.execute {
		// The approved request is spent by the call, so everything that can fail
		// locally (the destination, the passphrase) is settled before it.
		if sink, err = openExportSink(cmd, f.out); err != nil {
			return err
		}
		defer sink.discard()
		if req.Passphrase, err = readPassphrase(cmd, true); err != nil {
			return err
		}
	}
	api, err := newClient(cmd, env)
	if err != nil {
		return err
	}
	direct, err := api.ExportMasterKey(cmd.Context(), req)
	if err != nil {
		return err
	}
	if direct.Pending != nil {
		return emit(cmd, direct, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "export of %s requested: job %s is %s. Once it is approved, run:\n  sm secrets export-key %s --execute --out FILE\n",
				id, direct.Pending.Job.ID, direct.Pending.Job.State, id)
			return err
		})
	}
	if direct.Applied == nil || sink == nil {
		return smerr.New(smerr.CodeInternal, "", "the server answered neither an export nor a request")
	}
	return sink.write(direct.Applied.Export)
}

func exportKeyOffline(cmd *cobra.Command, env []string, id domain.ID, f exportFlags) error {
	sink, err := openExportSink(cmd, f.out)
	if err != nil {
		return err
	}
	defer sink.discard()
	passphrase, err := readPassphrase(cmd, true)
	if err != nil {
		return err
	}
	session, err := openOffline(cmd, env)
	if err != nil {
		return err
	}
	defer session.close()
	repo, err := session.repo(cmd.Context())
	if err != nil {
		return err
	}
	if repo == nil {
		return usageErrorf("there is no database at %s to check the key against: export from the host that has it", session.dbPath)
	}
	export, err := secrets.ExportKeyOffline(cmd.Context(), session.keysDir, repo, id, passphrase)
	if err != nil {
		return err
	}
	return sink.write(export)
}

// readPassphrase reads the passphrase of a key export (at least 12 characters).
func readPassphrase(cmd *cobra.Command, confirmEntry bool) (string, error) {
	passphrase, err := readSecret(cmd, secretInput{prompt: "Export passphrase: ", confirm: confirmEntry, limit: maxPassphraseBytes})
	if err != nil {
		return "", err
	}
	if len([]rune(passphrase)) < minPassphraseLength {
		return "", usageErrorf("the passphrase must have at least %d characters", minPassphraseLength)
	}
	return passphrase, nil
}

// exportSink is where a key export goes: a new owner-only file, or a stdout
// that is not a terminal. Binary key material is never dumped on a screen.
type exportSink struct {
	out     io.Writer
	file    *os.File
	path    string
	written bool
	errOut  io.Writer
}

func openExportSink(cmd *cobra.Command, path string) (*exportSink, error) {
	if path == "" {
		if file, ok := cmd.OutOrStdout().(*os.File); ok && isTerminal(file) {
			return nil, usageErrorf("refusing to print a key export on a terminal: pass --out FILE")
		}
		return &exportSink{out: cmd.OutOrStdout(), errOut: cmd.ErrOrStderr()}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen destination
	if err != nil {
		return nil, usageErrorf("cannot create %s: %v", path, err)
	}
	return &exportSink{out: f, file: f, path: path, errOut: cmd.ErrOrStderr()}, nil
}

func (s *exportSink) write(export []byte) error {
	if _, err := s.out.Write(export); err != nil {
		return fmt.Errorf("write the key export: %w", err)
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("write %s: %w", s.path, err)
		}
		s.file = nil
		_, _ = fmt.Fprintf(s.errOut, "wrote the key export to %s (mode 0600); keep it and its passphrase apart from your backups\n", s.path)
	}
	s.written = true
	return nil
}

// discard removes the empty file of an export that never happened.
func (s *exportSink) discard() {
	if s == nil || s.written || s.path == "" {
		return
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	_ = os.Remove(s.path)
}

// ---- import-key -------------------------------------------------------------------------

func newImportKeyCmd(env []string) *cobra.Command {
	var offline bool
	var from string
	cmd := &cobra.Command{
		Use:   "import-key",
		Short: "Install a master key from an export file (offline)",
		Long: "Install a master key from an SMKEY1 export, with the service stopped. It needs no database: the key waits as\n" +
			"<kek-id>.key.pending until a restore validates it, or is verified and activated at once when the database\n" +
			"here already references it. The passphrase is read from the terminal or standard input.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !offline {
				return usageErrorf("import-key only runs offline: stop the service and add --offline")
			}
			if from == "" {
				return usageErrorf("--from names the export file")
			}
			return importKeyOffline(cmd, env, from)
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "install the key without a running service (required)")
	cmd.Flags().StringVar(&from, "from", "", "the export file")
	return cmd
}

func importKeyOffline(cmd *cobra.Command, env []string, from string) error {
	export, err := os.ReadFile(filepath.Clean(from))
	if err != nil {
		return usageErrorf("cannot read %s: %v", from, err)
	}
	passphrase, err := readSecret(cmd, secretInput{prompt: "Export passphrase: ", limit: maxPassphraseBytes})
	if err != nil {
		return err
	}
	session, err := openOffline(cmd, env)
	if err != nil {
		return err
	}
	defer session.close()
	repo, err := session.repo(cmd.Context())
	if err != nil {
		return err
	}
	imported, err := secrets.ImportKey(cmd.Context(), session.keysDir, repo, export, passphrase)
	if err != nil {
		return err
	}
	report := map[string]any{"kek_id": imported.KEKID, "active": imported.Active, "keys_dir": session.keysDir}
	return emit(cmd, report, func(w io.Writer) error {
		if imported.Active {
			_, err := fmt.Fprintf(w, "key %s verified against the database and installed\n", imported.KEKID)
			return err
		}
		_, err := fmt.Fprintf(w, "key %s staged as %s.key.pending: a restore validates it against the restored database\n", imported.KEKID, imported.KEKID)
		return err
	})
}

// ---- offline session -----------------------------------------------------------------------

// offlineSession is a stopped control plane that a command works on directly:
// it holds the database lock and knows where the keys and the database are.
type offlineSession struct {
	cfg     *config.Config
	lock    *database.Lock
	dbPath  string
	keysDir string
	db      *database.ReadOnly
}

func openOffline(cmd *cobra.Command, env []string) (*offlineSession, error) {
	configFlag, _ := cmd.Flags().GetString("config")
	file := configPath(configFlag, env)
	result, err := config.Load(file, env)
	if err != nil {
		return nil, usageErrorf("configuration %s is invalid: %s", file, joinProblems(configProblems(err)))
	}
	cfg := result.Config
	dbPath, err := filepath.Abs(cfg.Storage.SQLite.Path)
	if err != nil {
		return nil, usageErrorf("storage.sqlite.path %q: %v", cfg.Storage.SQLite.Path, err)
	}
	keysDir, err := filepath.Abs(cfg.Security.KeysDir)
	if err != nil {
		return nil, usageErrorf("security.keys_dir %q: %v", cfg.Security.KeysDir, err)
	}
	lock, err := database.AcquireDatabaseLock(dbPath)
	if err != nil {
		return nil, fmt.Errorf("%w (stop the service first)", err)
	}
	return &offlineSession{cfg: cfg, lock: lock, dbPath: dbPath, keysDir: keysDir}, nil
}

// repo opens the database read-only as a secrets.Repo, or returns nil when
// there is no database with a schema yet (import-key then leaves the key pending).
func (s *offlineSession) repo(ctx context.Context) (secrets.Repo, error) {
	if _, err := os.Stat(s.dbPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil // no database is a valid state
	} else if err != nil {
		return nil, fmt.Errorf("stat the database: %w", err)
	}
	db, err := database.OpenReadOnly(ctx, s.dbPath)
	if err != nil {
		return nil, fmt.Errorf("open the database: %w", err)
	}
	hasSchema, err := db.HasSchema(ctx)
	if err != nil || !hasSchema {
		_ = db.Close()
		return nil, err
	}
	s.db = db
	return database.ReadOnlySecrets{Q: db.Querier()}, nil
}

// writableDatabase opens the database for writing. It must already exist with
// a schema: the service creates both on its first start.
func (s *offlineSession) writableDatabase(ctx context.Context) (*database.DB, error) {
	repo, err := s.repo(ctx)
	if err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, usageErrorf("there is no initialized database at %s: start the service once, then stop it and import", s.dbPath)
	}
	db, err := database.Open(ctx, s.dbPath, database.Options{})
	if err != nil {
		return nil, fmt.Errorf("open the database: %w", err)
	}
	return db, nil
}

func (s *offlineSession) close() {
	if s.db != nil {
		_ = s.db.Close()
	}
	_ = s.lock.Release()
}
