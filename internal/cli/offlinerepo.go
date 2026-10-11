package cli

import (
	"context"
	"errors"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

var errOfflineReadOnly = errors.New("the offline key commands never write to the database")

// offlineSecrets is the read-only view of the secrets table that import-key
// and export-key need: the key check records, and which keys rows reference.
type offlineSecrets struct{ q database.Querier }

var _ secrets.Repo = offlineSecrets{}

func (s offlineSecrets) Setting(ctx context.Context, key string) (string, bool, error) {
	setting, err := database.GetSetting(ctx, s.q, key)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(setting.Value), true, nil
}

func (s offlineSecrets) ReferencedKEKs(ctx context.Context) ([]domain.ID, error) {
	return database.ReferencedKEKIDs(ctx, s.q)
}

func (offlineSecrets) Put(context.Context, secrets.Record) error { return errOfflineReadOnly }

func (offlineSecrets) Get(context.Context, string, int) (secrets.Record, error) {
	return secrets.Record{}, errOfflineReadOnly
}

func (offlineSecrets) PutStaged(context.Context, secrets.Record) error { return errOfflineReadOnly }

func (offlineSecrets) GetByID(context.Context, domain.ID) (secrets.Record, error) {
	return secrets.Record{}, errOfflineReadOnly
}

func (offlineSecrets) ActivateStaged(context.Context, domain.ID) (secrets.Record, error) {
	return secrets.Record{}, errOfflineReadOnly
}

func (offlineSecrets) DeleteStaged(context.Context, domain.ID) error { return errOfflineReadOnly }

func (offlineSecrets) PutSettings(context.Context, map[string]string) error {
	return errOfflineReadOnly
}
