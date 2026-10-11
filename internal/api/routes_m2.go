package api

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth/oidc"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	actionTokenCreate      = "token.create"
	actionSecretWrite      = "secret.write"
	actionBackupRead       = "backup.read"
	actionBackupCreate     = "backup.create"
	actionEnrollmentCreate = "enrollment.create"
	actionEventRead        = "event.read"
)

func unavailable(what string) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "", what+" is not available on this instance")
}

// ---- login and sessions (ADR-0017, ADR-0018) --------------------------------

func (rs *routeSet) login() {
	s := rs.s
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathOIDCStart, action: ExemptAuth, auth: authNone, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			req, err := decode[wire.OIDCStartRequest](in)
			if err != nil {
				return nil, err
			}
			return a.OIDCStart(ctx, req)
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathOIDCExchange, action: ExemptAuth, auth: authNone, credential: true, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			req, err := decode[wire.OIDCExchangeRequest](in)
			if err != nil {
				return nil, err
			}
			return a.OIDCExchange(ctx, req)
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathOIDCDevice, action: ExemptAuth, auth: authNone, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, _ input) (any, error) {
			return a.DeviceStart(ctx)
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathOIDCDevicePoll, action: ExemptAuth, auth: authNone, credential: true, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			req, err := decode[wire.DevicePollRequest](in)
			if err != nil {
				return nil, err
			}
			return a.DevicePoll(ctx, req)
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathBootstrap, action: ExemptAuth, auth: authOptional, credential: true, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, s.bootstrap),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathLogout, action: ExemptAuth, maxBody: maxAuthBodyBytes,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			return struct{}{}, a.Logout(ctx, scopeOf(ctx).caller)
		}),
	})
}

// publicCall adapts a call of the Auth service: unkeyed, answering with the
// wire value itself.
func (s *Server) publicCall(status int, call func(ctx context.Context, a app.Auth, in input) (any, error)) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.svc.Auth == nil {
			return unavailable("authentication")
		}
		in, err := readInput(r)
		if err != nil {
			return err
		}
		ctx := oidc.WithClient(r.Context(), scopeOf(r.Context()).client.String())
		out, err := call(ctx, s.svc.Auth, in)
		if err != nil {
			return err
		}
		s.writeData(w, r, status, out)
		return nil
	}
}

// bootstrap exchanges a bootstrap code (spec §11.5). The session of a
// completed OIDC login, when one is sent, is the identity bound to admin.
func (s *Server) bootstrap(ctx context.Context, a app.Auth, in input) (any, error) {
	req, err := decode[wire.BootstrapRequest](in)
	if err != nil {
		return nil, err
	}
	var session *app.Caller
	if by := scopeOf(ctx).caller; by.Credential.Kind == domain.CredentialSession {
		session = &by
	}
	return a.Bootstrap(ctx, session, req)
}

// ---- API tokens (spec §23) ---------------------------------------------------

func (rs *routeSet) tokens() {
	s := rs.s
	rs.add(route{
		method: http.MethodGet, pattern: wire.PathTokens, action: ExemptSelf,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			tokens, err := a.ListTokens(ctx, scopeOf(ctx).caller)
			if tokens == nil {
				tokens = []wire.Token{}
			}
			return wire.Page[wire.Token]{Items: tokens}, err
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathTokens, action: actionTokenCreate, credential: true,
		do: s.publicCall(http.StatusCreated, func(ctx context.Context, a app.Auth, in input) (any, error) {
			req, err := decode[wire.CreateTokenRequest](in)
			if err != nil {
				return nil, err
			}
			return a.CreateToken(ctx, scopeOf(ctx).caller, req)
		}),
	})
	rs.add(route{
		method: http.MethodDelete, pattern: wire.PathToken, action: ExemptSelf,
		do: s.publicCall(http.StatusOK, func(ctx context.Context, a app.Auth, in input) (any, error) {
			id, err := in.id("id")
			if err != nil {
				return nil, err
			}
			return struct{}{}, a.RevokeToken(ctx, scopeOf(ctx).caller, id)
		}),
	})
}

// ---- keys and secrets (ADR-0021) ---------------------------------------------

func (rs *routeSet) keys() {
	s := rs.s
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathSecrets, action: actionSecretWrite, keyed: true, maxBody: maxSecretBytes,
		do: s.requireKeys(operation(s, func(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.SecretVersion], error) {
			req, err := decode[wire.ImportSecretRequest](in)
			if err != nil {
				return app.DirectResult[wire.SecretVersion]{}, err
			}
			return s.svc.Keys.ImportSecret(ctx, by, req)
		})),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathMasterKeyRotate, action: actionSecretWrite, keyed: true,
		do: s.requireKeys(operation(s, func(ctx context.Context, by app.Caller, _ input) (app.DirectResult[wire.MasterKeyRotated], error) {
			return s.svc.Keys.RotateMasterKey(ctx, by)
		})),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathMasterKeyRetire, action: actionSecretWrite, keyed: true,
		do: s.requireKeys(operation(s, func(ctx context.Context, by app.Caller, in input) (app.DirectResult[struct{}], error) {
			req, err := decode[wire.RetireKeyRequest](in)
			if err != nil {
				return app.DirectResult[struct{}]{}, err
			}
			return s.svc.Keys.RetireKey(ctx, by, req)
		})),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathSSHKeyRotate, action: actionSecretWrite, keyed: true,
		do: s.requireKeys(operation(s, func(ctx context.Context, by app.Caller, _ input) (app.DirectResult[wire.SSHKey], error) {
			return s.svc.Keys.RotateSSHIdentity(ctx, by)
		})),
	})
	rs.add(route{
		method: http.MethodGet, pattern: wire.PathMasterKeys, action: actionConfigRead,
		do: s.requireKeys(reading(s, s.listMasterKeys)),
	})
	// Export answers with a wrapped master key. It exists only on the local
	// socket (spec §10) and never goes through the Idempotency-Key store: the
	// execution is single-use by itself (ADR-0021).
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathMasterKeyExport, action: actionSecretWrite, credential: true, unixOnly: true,
		do: s.requireKeys(func(w http.ResponseWriter, r *http.Request) error {
			in, err := readInput(r)
			if err != nil {
				return err
			}
			req, err := decode[wire.ExportKeyRequest](in)
			if err != nil {
				return err
			}
			res, err := s.svc.Keys.ExportKey(r.Context(), scopeOf(r.Context()).caller, req)
			if err != nil {
				return err
			}
			status, data := direct(http.StatusOK, same[wire.ExportedKey])(res)
			s.writeData(w, r, status, data)
			return nil
		}),
	})
}

func (s *Server) listMasterKeys(ctx context.Context, by app.Caller, _ input) (wire.Page[wire.MasterKey], error) {
	keys, err := s.svc.Keys.ListKeys(ctx, by)
	if keys == nil {
		keys = []wire.MasterKey{}
	}
	return wire.Page[wire.MasterKey]{Items: keys}, err
}

func (s *Server) requireKeys(next endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.svc.Keys == nil {
			return unavailable("key management")
		}
		return next(w, r)
	}
}

// ---- backups (spec §29.1) ----------------------------------------------------

func (rs *routeSet) backups() {
	s := rs.s
	rs.add(route{
		method: http.MethodGet, pattern: wire.PathBackups, action: actionBackupRead,
		do: s.requireBackups(reading(s, func(ctx context.Context, by app.Caller, _ input) (wire.Page[wire.Backup], error) {
			archives, err := s.svc.Backups.List(ctx, by)
			if archives == nil {
				archives = []wire.Backup{}
			}
			return wire.Page[wire.Backup]{Items: archives}, err
		})),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathBackups, action: actionBackupCreate, keyed: true,
		do: s.requireBackups(mutation(s, func(ctx context.Context, by app.Caller, _ input) (app.Submission, error) {
			return s.svc.Backups.Create(ctx, by)
		}, submitted)),
	})
}

func (s *Server) requireBackups(next endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.svc.Backups == nil {
			return unavailable("backups")
		}
		return next(w, r)
	}
}

// ---- enrollment (ADR-0022) ---------------------------------------------------

func (rs *routeSet) enrollment() {
	s := rs.s
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathEnrollments, action: actionEnrollmentCreate, credential: true,
		do: s.requireEnrollments(func(w http.ResponseWriter, r *http.Request) error {
			in, err := readInput(r)
			if err != nil {
				return err
			}
			req, err := decode[wire.EnrollmentRequest](in)
			if err != nil {
				return err
			}
			issued, err := s.svc.Enrollments.Create(r.Context(), scopeOf(r.Context()).caller, req)
			if err != nil {
				return err
			}
			s.writeData(w, r, http.StatusCreated, issued)
			return nil
		}),
	})
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathEnroll, action: ExemptAuth, auth: authNone, credential: true, maxBody: maxAuthBodyBytes,
		do: s.requireEnrollments(func(w http.ResponseWriter, r *http.Request) error {
			in, err := readInput(r)
			if err != nil {
				return err
			}
			req, err := decode[wire.EnrollRequest](in)
			if err != nil {
				return err
			}
			source := scopeOf(r.Context()).client
			if !source.IsValid() {
				return invalid("the source address of the request is unknown")
			}
			enrolled, err := s.svc.Enrollments.Enroll(r.Context(), source, req)
			if err != nil {
				return err
			}
			s.writeData(w, r, http.StatusOK, enrolled)
			return nil
		}),
	})
}

func (s *Server) requireEnrollments(next endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.svc.Enrollments == nil {
			return unavailable("enrollment")
		}
		return next(w, r)
	}
}

func (rs *routeSet) add(rt route) { rs.routes = append(rs.routes, rt) }
