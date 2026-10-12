package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// sourceValidationProject names the compose project while a source is
// validated without a target.
const sourceValidationProject = "sm-source-validation"

// ValidateSource runs spec §20.3 steps 1-7 on a source without binding it to a
// target. The bind policy belongs to a target, so every non-loopback host_ip
// the source itself declares is accepted here; Freeze enforces the policy of
// each real target.
func ValidateSource(s Source) error {
	root, err := parseMerged(s.Raw)
	if err != nil {
		return err
	}
	t := Target{Project: sourceValidationProject, AllowedBind: declaredHostIPs(root)}
	_, err = checkSource(s, t)
	return err
}

// Freeze runs spec §20.3 steps 1-9 for one target: it validates, rewrites and
// binds images, validates again, labels every resource, and returns the
// canonical public model with its hash and the expected effective model.
// The same source frozen for two targets yields two models.
func Freeze(s Source, t Target) (Frozen, error) {
	if t.Project == "" || t.Owner == "" {
		return Frozen{}, smerr.New(smerr.CodeInvalidArgument, "", "a target needs a compose project and an owner")
	}
	checked, err := checkSource(s, t)
	if err != nil {
		return Frozen{}, err
	}
	root, err := parseMerged(checked.interpolated)
	if err != nil {
		return Frozen{}, err
	}
	images, err := bindImages(root.get("services"), s)
	if err != nil {
		return Frozen{}, err
	}
	if err := checkRewritten(root, s, t); err != nil {
		return Frozen{}, err
	}
	labelResources(root, t)
	public, err := canonicalYAML(root)
	if err != nil {
		return Frozen{}, err
	}
	project, err := Load(public, t.Project)
	if err != nil {
		return Frozen{}, err
	}
	effective, err := maskedEffectiveModel(project)
	if err != nil {
		return Frozen{}, err
	}
	return Frozen{
		Public:    public,
		Hash:      canonicalHash(public),
		Effective: effective,
		Images:    images,
		Secrets:   checked.secrets,
		HostPorts: hostPorts(project),
	}, nil
}

type checkedSource struct {
	interpolated []byte
	secrets      []SecretUse
}

// checkSource is steps 1-7: raw checks, interpolation, load, model checks.
func checkSource(s Source, t Target) (checkedSource, error) {
	if err := CheckRaw(s.Raw, t); err != nil {
		return checkedSource{}, err
	}
	interpolated, secrets, err := interpolate(s.Raw, s)
	if err != nil {
		return checkedSource{}, err
	}
	if err := checkLoaded(interpolated, s, t); err != nil {
		return checkedSource{}, err
	}
	return checkedSource{interpolated: interpolated, secrets: secrets}, nil
}

// checkRewritten is step 8's "validation (step 5) runs after the rewrite".
func checkRewritten(root *node, s Source, t Target) error {
	rewritten, err := encode(root)
	if err != nil {
		return err
	}
	if err := CheckRaw(rewritten, t); err != nil {
		return err
	}
	return checkLoaded(rewritten, s, t)
}

func checkLoaded(document []byte, s Source, t Target) error {
	project, err := Load(document, t.Project)
	if err != nil {
		return err
	}
	return CheckModel(project, t, s.Exceptions)
}

func declaredHostIPs(root *node) []netip.Addr {
	var addrs []netip.Addr
	services := root.get("services")
	if services == nil {
		return nil
	}
	for _, svc := range services.entries {
		ports := svc.val.get("ports")
		if ports == nil {
			continue
		}
		for _, port := range ports.items {
			if ip := port.get("host_ip"); ip != nil {
				if addr, err := netip.ParseAddr(ip.value); err == nil {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	return addrs
}

func hostPorts(p *types.Project) []HostPort {
	var out []HostPort
	for name, svc := range p.Services {
		for _, port := range svc.Ports {
			published, err := strconv.ParseUint(port.Published, 10, 16)
			addr, addrErr := netip.ParseAddr(port.HostIP)
			if err != nil || addrErr != nil {
				continue // CheckModel guarantees both; nothing publishes otherwise
			}
			out = append(out, HostPort{Service: name, Addr: addr, Port: uint16(published), Proto: protocolOf(port.Protocol)})
		}
	}
	slices.SortFunc(out, func(a, b HostPort) int {
		if c := strings.Compare(a.Service, b.Service); c != 0 {
			return c
		}
		if c := a.Addr.Compare(b.Addr); c != 0 {
			return c
		}
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return strings.Compare(a.Proto, b.Proto)
	})
	return out
}

func protocolOf(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

// maskedEffectiveModel renders the model the pinned loader produced with every
// environment value replaced by sha256:<hex> of its resolved value, the same
// masking the node applies (ADR-0010). Values written as "$$" resolve to "$".
func maskedEffectiveModel(p *types.Project) (json.RawMessage, error) {
	doc, err := modelDocument(p)
	if err != nil {
		return nil, err
	}
	services, _ := doc["services"].(map[string]any)
	for _, svc := range services {
		fields, _ := svc.(map[string]any)
		if env, ok := fields["environment"].(map[string]any); ok {
			maskEnvironment(env)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode effective model: %w", err)
	}
	return json.RawMessage(bytes.TrimSpace(buf.Bytes())), nil
}

func maskEnvironment(env map[string]any) {
	for name, value := range env {
		text, ok := value.(string)
		if !ok {
			env[name] = nil
			continue
		}
		sum := sha256.Sum256([]byte(strings.ReplaceAll(text, "$$", "$")))
		env[name] = "sha256:" + hex.EncodeToString(sum[:])
	}
}
