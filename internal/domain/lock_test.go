package domain_test

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestLockKeys(t *testing.T) {
	tests := []struct {
		name string
		got  domain.LockSpec
		want domain.LockSpec
	}{
		{
			"resource",
			domain.ResourceLock(domain.ResourceRef{Type: domain.ResourceAppTarget, ID: "abc"}, domain.LockExclusive),
			domain.LockSpec{Key: "app_target:abc", Mode: domain.LockExclusive},
		},
		{
			"compose project",
			domain.ComposeProjectLock("node1", "sm-web-prod", domain.LockExclusive),
			domain.LockSpec{Key: "compose_project:node1:sm-web-prod", Mode: domain.LockExclusive},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %+v, want %+v", tt.got, tt.want)
			}
		})
	}
}
