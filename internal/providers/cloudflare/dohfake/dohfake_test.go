package dohfake_test

import (
	"context"
	"errors"
	"testing"

	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/dohfake"
)

const host = "ssh-vps1.example.test"

func TestTheCheckerSeesTheStateTheFakeIsIn(t *testing.T) {
	tests := []struct {
		name      string
		mode      dohfake.Mode
		published bool
		cannotAsk bool
	}{
		{"not served is not published yet", dohfake.NotServed, false, false},
		{"served is published", dohfake.Served, true, false},
		{"no data is not published yet", dohfake.NoData, false, false},
		{"a stale positive answer is published", dohfake.Stale, true, false},
		{"servfail cannot be asked", dohfake.ServFail, false, true},
		{"an unreachable resolver cannot be asked", dohfake.Unreachable, false, true},
		{"a malformed reply cannot be asked", dohfake.Malformed, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dohfake.New(t)
			f.Set(tt.mode)
			published, err := f.Checker().Published(context.Background(), host)
			if published != tt.published || errors.Is(err, cloudflare.ErrResolverUnavailable) != tt.cannotAsk {
				t.Errorf("published = %v, err = %v; want published %v, cannot ask %v", published, err, tt.published, tt.cannotAsk)
			}
		})
	}
}

func TestAHostnameServedAfterNQuestionsIsNotPublishedBeforeThat(t *testing.T) {
	f := dohfake.New(t)
	f.PublishAfter(3)
	checker := f.Checker()
	var answers []bool
	for range 5 {
		published, err := checker.Published(context.Background(), host)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, published)
	}
	want := []bool{false, false, false, true, true}
	for i := range want {
		if answers[i] != want[i] {
			t.Fatalf("answers = %v, want %v", answers, want)
		}
	}
	if f.Asked(host) < 5 {
		t.Errorf("asked %d times", f.Asked(host))
	}
}
