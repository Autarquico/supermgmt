package daemon

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oidc"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	idpTimeout       = 15 * time.Second
	idpMaxBody       = 1 << 20
	discoveryTimeout = 30 * time.Second
)

// login is nil when OIDC is not configured, which changes the bootstrap
// exchange (spec §11.5). Otherwise it is an adapter that discovers the IdP
// on first use: an IdP that is down must not stop the control plane from
// starting, and the client secret may be imported after the start.
func (b *builder) login() (oidc.Login, error) {
	c := b.cfg.Auth.OIDC
	if !c.Enabled {
		return nil, nil
	}
	ref, err := parseSecretRef(c.ClientSecretRef)
	if err != nil {
		return nil, fmt.Errorf("auth.oidc.client_secret_ref: %w", err)
	}
	proxy, err := outboundProxy(b.cfg.Outbound.Proxy)
	if err != nil {
		return nil, err
	}
	httpClient := netguard.NewClient(netguard.Allow{AllowAllPrivate: true}, proxy, idpTimeout, idpMaxBody)
	return &lazyLogin{build: func(ctx context.Context) (oidc.Login, error) {
		secret, err := b.kit.store.Get(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("read the OIDC client secret %s: %w", ref, err)
		}
		return oidc.New(ctx, oidc.Config{
			Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: secret, AllowedDomains: c.AllowedDomains,
			AllowedEndpointOrigins: c.AllowedEndpointOrigins, HTTPClient: httpClient, Clock: b.o.Clock,
			Replay: auth.OIDCReplay{DB: b.db},
		})
	}}, nil
}

func outboundProxy(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("outbound.proxy: %w", err)
	}
	return u, nil
}

// parseSecretRef reads secret://name or secret://name@version.
func parseSecretRef(raw string) (secrets.Ref, error) {
	name, found := strings.CutPrefix(raw, "secret://")
	if !found || name == "" {
		return secrets.Ref{}, fmt.Errorf("%q is not a secret:// reference", raw)
	}
	if at := strings.LastIndex(name, "@"); at >= 0 {
		version, err := strconv.Atoi(name[at+1:])
		if err != nil || version < 1 {
			return secrets.Ref{}, fmt.Errorf("%q has a malformed version", raw)
		}
		return secrets.Ref{Name: name[:at], Version: version}, nil
	}
	return secrets.Ref{Name: name}, nil
}

// lazyLogin is an oidc.Login that builds the real adapter on first use and
// keeps trying until that works.
type lazyLogin struct {
	build func(context.Context) (oidc.Login, error)

	mu    sync.Mutex
	ready oidc.Login
}

var _ oidc.Login = (*lazyLogin)(nil)

func (l *lazyLogin) get(ctx context.Context) (oidc.Login, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ready != nil {
		return l.ready, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
	defer cancel()
	built, err := l.build(ctx)
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeProviderError, "", "the identity provider cannot be reached or is misconfigured")
	}
	l.ready = built
	return built, nil
}

func (l *lazyLogin) Start(ctx context.Context, redirect, challenge string) (string, string, error) {
	login, err := l.get(ctx)
	if err != nil {
		return "", "", err
	}
	return login.Start(ctx, redirect, challenge)
}

func (l *lazyLogin) Exchange(ctx context.Context, code, state, verifier string) (oidc.Claims, error) {
	login, err := l.get(ctx)
	if err != nil {
		return oidc.Claims{}, err
	}
	return login.Exchange(ctx, code, state, verifier)
}

func (l *lazyLogin) DeviceStart(ctx context.Context) (oidc.DeviceTxn, error) {
	login, err := l.get(ctx)
	if err != nil {
		return oidc.DeviceTxn{}, err
	}
	return login.DeviceStart(ctx)
}

func (l *lazyLogin) DevicePoll(ctx context.Context, txnID string) (oidc.Claims, error) {
	login, err := l.get(ctx)
	if err != nil {
		return oidc.Claims{}, err
	}
	return login.DevicePoll(ctx, txnID)
}
