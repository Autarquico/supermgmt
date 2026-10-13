package compose

import (
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const imageRedisRepo = "docker.io/library/redis"

func imageDigestOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func imageFreezeWithRedis(s Source, redisImage string) error {
	s.Raw = []byte(strings.Replace(freezeDocument, freezeRedis, redisImage, 1))
	_, err := Freeze(s, freezeTarget("prod"))
	return err
}

func TestBindImages_SidecarRejections(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  smerr.Reason
	}{
		{"tag", imageRedisRepo + ":7", smerr.ReasonTagReference},
		{"no tag, no digest", imageRedisRepo, smerr.ReasonTagReference},
		{"tag and digest", imageRedisRepo + ":7@" + imageDigestOf("3"), smerr.ReasonTagReference},
		{"other repository", "docker.io/evil/redis@" + imageDigestOf("3"), smerr.ReasonComposeRejected},
		{"short digest", imageRedisRepo + "@sha256:abc", smerr.ReasonComposeRejected},
		{"unbound digest", imageRedisRepo + "@" + imageDigestOf("4"), smerr.ReasonDigestUnbound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := freezeReasonOf(imageFreezeWithRedis(freezeSource(), tc.image)); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBindImages_PinnedDigestIsBound(t *testing.T) {
	ref := imageRedisRepo + "@" + imageDigestOf("4")
	s := freezeSource()
	s.Images.Pinned = []string{ref}
	s.Raw = []byte(strings.Replace(freezeDocument, freezeRedis, ref, 1))
	f := freezeOK(t, s, freezeTarget("prod"))
	if got := f.Images[1]; got.Ref != ref || got.Binding != BindingPinned {
		t.Fatalf("redis image = %+v", got)
	}
}

func TestBindImages_UnlistedServiceIsRejected(t *testing.T) {
	s := freezeSource()
	s.Images.Sidecars = nil
	if got := freezeReasonOf(imageFreezeWithRedis(s, freezeRedis)); got != smerr.ReasonComposeRejected {
		t.Fatalf("reason = %q", got)
	}
}

func TestBindImages_DeployedServiceRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Source)
		want   smerr.Reason
	}{
		{"unbound artifact", func(s *Source) { s.BoundDigests = map[string]string{freezeRedis: BindingPinned} }, smerr.ReasonDigestUnbound},
		{"missing artifact digest", func(s *Source) { s.ArtifactDigest = "" }, smerr.ReasonDigestUnbound},
		{"malformed artifact digest", func(s *Source) { s.ArtifactDigest = "sha256:XYZ" }, smerr.ReasonDigestUnbound},
		{"unknown binding", func(s *Source) { s.BoundDigests[freezeAPIRef] = "trust-me" }, smerr.ReasonDigestUnbound},
		{"provenance required, deployed digest only pinned", func(s *Source) { s.RequireProvenance, s.BoundDigests[freezeAPIRef] = true, BindingPinned }, smerr.ReasonDigestUnbound},
		{"deployed service missing", func(s *Source) { s.DeployedService = "ghost" }, smerr.ReasonComposeRejected},
		{"repository with tag", func(s *Source) { s.Images.Deployed = "ghcr.io/acme/api:1" }, smerr.ReasonComposeRejected},
		{"no repository", func(s *Source) { s.Images.Deployed = "" }, smerr.ReasonComposeRejected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := freezeSource()
			tc.mutate(&s)
			_, err := Freeze(s, freezeTarget("prod"))
			if got := freezeReasonOf(err); got != tc.want {
				t.Fatalf("reason = %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestHasTag_RegistryPortIsNotATag(t *testing.T) {
	tests := map[string]bool{
		"localhost:5000/acme/api": false,
		"acme/api:1":              true,
		"api:latest":              true,
		"ghcr.io/acme/api":        false,
	}
	for repo, want := range tests {
		if got := hasTag(repo); got != want {
			t.Errorf("hasTag(%q) = %v, want %v", repo, got, want)
		}
	}
}

func TestBindImages_RequireProvenanceAcceptsAnAttestedDeployedServiceAndPinnedSidecars(t *testing.T) {
	ref := imageRedisRepo + "@" + imageDigestOf("4")
	s := freezeSource()
	s.RequireProvenance = true
	s.BoundDigests[freezeAPIRef] = BindingAttestation
	s.Images.Pinned = []string{ref}
	s.Raw = []byte(strings.Replace(freezeDocument, freezeRedis, ref, 1))
	f := freezeOK(t, s, freezeTarget("prod"))
	if f.Images[0].Binding != BindingAttestation || f.Images[1].Binding != BindingPinned {
		t.Fatalf("images = %+v", f.Images)
	}
}
