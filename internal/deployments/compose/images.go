package compose

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// bindImages performs spec §20.3 step 8 on the services mapping, in place:
// the deployed service's image becomes <deployed repository>@<artifact digest>,
// every other service must already name its allowed repository by digest, and
// every resulting digest must be bound (§18) or pinned. It returns one
// ImageUse per service, ordered by service name.
func bindImages(services *node, s Source) ([]ImageUse, error) {
	if services.get(s.DeployedService) == nil {
		return nil, imageError(smerr.ReasonComposeRejected, s.DeployedService, "the deployed service is not defined")
	}
	var uses []ImageUse
	for _, e := range canonicalEntries(services) {
		image := e.val.get("image")
		ref, err := imageReference(e.key, image.value, s)
		if err != nil {
			return nil, err
		}
		binding, err := imageBinding(e.key, ref, s)
		if err != nil {
			return nil, err
		}
		if e.key == s.DeployedService && s.RequireProvenance && binding != BindingAttestation {
			return nil, imageError(smerr.ReasonDigestUnbound, e.key, "%s has no attestation and the environment requires provenance", ref)
		}
		image.value = ref
		uses = append(uses, ImageUse{Service: e.key, Ref: ref, Binding: binding})
	}
	return uses, nil
}

func imageReference(service, current string, s Source) (string, error) {
	if service == s.DeployedService {
		return deployedReference(service, s)
	}
	return sidecarReference(service, current, s.Images.Sidecars)
}

func deployedReference(service string, s Source) (string, error) {
	repository := s.Images.Deployed
	if repository == "" || strings.Contains(repository, "@") || hasTag(repository) {
		return "", imageError(smerr.ReasonComposeRejected, service, "image_policy.deployed must be a bare repository")
	}
	if !imageDigest.MatchString(s.ArtifactDigest) {
		return "", imageError(smerr.ReasonDigestUnbound, service, "the artifact digest is missing or malformed")
	}
	return repository + "@" + s.ArtifactDigest, nil
}

func sidecarReference(service, current string, allowed map[string]string) (string, error) {
	repository, ok := allowed[service]
	if !ok {
		return "", imageError(smerr.ReasonComposeRejected, service, "the image policy does not allow this service")
	}
	name, digest, pinnedByDigest := strings.Cut(current, "@")
	if !pinnedByDigest || hasTag(name) {
		return "", imageError(smerr.ReasonTagReference, service, "the image must be %s@sha256:<digest>, tags are not allowed", repository)
	}
	if name != repository {
		return "", imageError(smerr.ReasonComposeRejected, service, "the image repository must be %s", repository)
	}
	if !imageDigest.MatchString(digest) {
		return "", imageError(smerr.ReasonComposeRejected, service, "the image digest must be sha256:<64 hex>")
	}
	return current, nil
}

func imageBinding(service, ref string, s Source) (string, error) {
	if binding, ok := s.BoundDigests[ref]; ok {
		if !slices.Contains([]string{BindingAttestation, BindingOIDCClaims, BindingPinned}, binding) {
			return "", imageError(smerr.ReasonDigestUnbound, service, "%s has an unknown binding", ref)
		}
		return binding, nil
	}
	if slices.Contains(s.Images.Pinned, ref) {
		return BindingPinned, nil
	}
	return "", imageError(smerr.ReasonDigestUnbound, service, "%s is neither bound nor pinned", ref)
}

// hasTag reports whether the last path segment of a repository carries ":tag"
// (a colon in an earlier segment is a registry port).
func hasTag(repository string) bool {
	segment := repository[strings.LastIndex(repository, "/")+1:]
	return strings.Contains(segment, ":")
}

func imageError(reason smerr.Reason, service, format string, args ...any) error {
	path := "services." + service + ".image"
	e := smerr.FromReason(reason, path+": "+fmt.Sprintf(format, args...))
	e.Details = map[string]any{"path": path}
	return e
}
