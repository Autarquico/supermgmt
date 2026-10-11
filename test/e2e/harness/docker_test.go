//go:build e2e

package harness

import (
	"regexp"
	"strings"
	"testing"
)

func TestRandomSubnetStaysInTheReservedRange(t *testing.T) {
	re := regexp.MustCompile(`^10\.213\.\d{1,3}\.0/24$`)
	for range 50 {
		if s := randomSubnet(); !re.MatchString(s) {
			t.Fatalf("randomSubnet = %q", s)
		}
	}
}

func TestCreateOnFreeSubnetRetriesWhenThePoolOverlaps(t *testing.T) {
	var tried []string
	picks := []string{"a", "b", "c"}
	pick := func() string { s := picks[len(tried)]; return s }
	create := func(subnet string) (Result, error) {
		tried = append(tried, subnet)
		if len(tried) < 3 {
			return Result{Code: 1, Stderr: "Error response from daemon: Pool overlaps with other one on this address space"}, nil
		}
		return Result{}, nil
	}

	if err := createOnFreeSubnet(create, pick); err != nil {
		t.Fatalf("createOnFreeSubnet: %v", err)
	}
	if strings.Join(tried, ",") != "a,b,c" {
		t.Fatalf("tried %v, want each attempt on a new subnet", tried)
	}
}

func TestCreateOnFreeSubnetStopsOnOtherErrors(t *testing.T) {
	calls := 0
	create := func(string) (Result, error) {
		calls++
		return Result{Code: 1, Stderr: "permission denied"}, nil
	}

	err := createOnFreeSubnet(create, func() string { return "x" })

	if err == nil || calls != 1 || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v after %d calls; want one call and the daemon's message", err, calls)
	}
}
