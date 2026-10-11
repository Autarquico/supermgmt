package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	actionConfigRead      = "config.read"
	activeKEKSetting      = "active_kek_id"
	kekCheckSettingPrefix = "kek_check."
)

// ListKeys describes the master keys the database knows (action config.read,
// ADR-0012): the id, whether it is the active one, whether this process holds
// it, and when it was created. It never reads key material. A key's creation
// time is that of its check record, which is written once with the key.
func (k *KeyManager) ListKeys(ctx context.Context, by Caller) ([]wire.MasterKey, error) {
	if _, err := k.authorizeOn(ctx, by, actionConfigRead, domain.ResourceRef{Type: domain.ResourceInstance}); err != nil {
		return nil, err
	}
	reader := k.cfg.DB.Reader()
	active, err := activeKEK(ctx, reader)
	if err != nil {
		return nil, err
	}
	checks, err := database.ListSettings(ctx, reader, kekCheckSettingPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]wire.MasterKey, 0, len(checks))
	for _, check := range checks {
		id, err := domain.ParseID(strings.TrimPrefix(check.Key, kekCheckSettingPrefix))
		if err != nil {
			return nil, fmt.Errorf("setting %s: %w", check.Key, err)
		}
		out = append(out, wire.MasterKey{ID: id, Active: id == active, Loaded: k.admin.Loaded(id), CreatedAt: check.UpdatedAt})
	}
	return out, nil
}

// activeKEK is the id in settings.active_kek_id, or "" before the first key.
func activeKEK(ctx context.Context, q database.Querier) (domain.ID, error) {
	setting, err := database.GetSetting(ctx, q, activeKEKSetting)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var id domain.ID
	if err := json.Unmarshal(setting.Value, &id); err != nil {
		return "", fmt.Errorf("setting %s: %w", activeKEKSetting, err)
	}
	return id, nil
}
