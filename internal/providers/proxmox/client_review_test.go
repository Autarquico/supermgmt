package proxmox_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

// SEC-12: upstream matches userfilter on the user, never on a token id, and
// lists only finished tasks unless source asks for the running ones too.
func TestTasksFindsARunningTokenTask(t *testing.T) {
	e := newEnv(t, pvefake.WithManualTasks())
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	upid, outcome, err := e.client.Power(context.Background(), ref, "stop")
	if outcome != proxmox.PowerAccepted {
		t.Fatal(outcome, err)
	}
	tasks, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{VMID: 100, TypeName: "qmstop", User: "root@pam!admin"})
	if err != nil || len(tasks) != 1 || tasks[0].UPID.Raw != upid.Raw || tasks[0].Stopped() {
		t.Fatalf("Tasks = %+v, %v; want the running task", tasks, err)
	}
	other, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{User: "other@pam!admin"})
	if err != nil || len(other) != 0 {
		t.Errorf("another user's filter returned %+v, %v", other, err)
	}
}

// SEC-10: a UPID that cannot belong to the request is not accepted.
func TestPowerRefusesAUPIDThatIsNotTheRequestsTask(t *testing.T) {
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	tests := map[string]string{
		"other guest": "UPID:pve1:000003E9:000003E9:6B49D200:qmstop:101:root@pam!admin:",
		"other verb":  "UPID:pve1:000003E9:000003E9:6B49D200:qmstart:100:root@pam!admin:",
		"other type":  "UPID:pve1:000003E9:000003E9:6B49D200:vzstop:100:root@pam!admin:",
		"other node":  "UPID:pve2:000003E9:000003E9:6B49D200:qmstop:100:root@pam!admin:",
		"other token": "UPID:pve1:000003E9:000003E9:6B49D200:qmstop:100:root@pam!other:",
		"no token":    "UPID:pve1:000003E9:000003E9:6B49D200:qmstop:100:root@pam:",
	}
	for name, upid := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(200, `{"data":"`+upid+`"}`)})
			got, outcome, err := e.client.Power(context.Background(), ref, "stop")
			if outcome != proxmox.PowerUncertain || err == nil || got.Raw != "" {
				t.Fatalf("outcome %d, upid %+v, err %v; want uncertain with no UPID", outcome, got, err)
			}
		})
	}
}

// SEC-18: the token is removed before the text is cut, so no part of it
// survives a cut that lands inside it.
func TestTruncationNeverLeavesAPieceOfTheToken(t *testing.T) {
	e := newEnv(t)
	secret := secretOf(e.token)
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	for _, padding := range []int{250, 270, 285, 290, 299} {
		long := strings.Repeat("x", padding) + e.token + " and more"
		body := fmt.Sprintf(`{"data":null,"message":%q}`, long)
		e.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.Respond(500, body)})
		_, _, err := e.client.Power(context.Background(), ref, "stop")
		var api *proxmox.APIError
		if !errors.As(err, &api) {
			t.Fatalf("padding %d: %v", padding, err)
		}
		for _, piece := range []string{secret[:6], secret[len(secret)-6:]} {
			if strings.Contains(api.Message, piece) {
				t.Errorf("padding %d leaves %q in %q", padding, piece, api.Message)
			}
		}
	}
}

func TestExitStatusFromPVEIsSanitizedAtTheClientBoundary(t *testing.T) {
	e := newEnv(t, pvefake.WithManualTasks())
	ctx := context.Background()
	upid, _, _ := e.client.Power(ctx, proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}, "stop")
	e.fake.FinishTask(upid.Raw, "\x1b[31mcommand failed\x1b[0m\nwith "+e.token+" "+strings.Repeat("y", 400))

	status, err := e.client.Task(ctx, upid)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := e.client.Tasks(ctx, "pve1", proxmox.TaskFilter{VMID: 100})
	if err != nil || len(listed) != 1 {
		t.Fatalf("Tasks = %+v, %v", listed, err)
	}
	for name, exit := range map[string]string{"status": status.ExitStatus, "list": listed[0].ExitStatus} {
		if strings.ContainsAny(exit, "\x1b\n") || strings.Contains(exit, secretOf(e.token)) || len(exit) > 310 || !strings.HasPrefix(exit, "command failed") {
			t.Errorf("%s exit status = %q", name, exit)
		}
	}
	if status.ExitStatus != listed[0].ExitStatus {
		t.Error("both reads of one task must agree: the fingerprint pairs samples on the exit status")
	}
}

func TestCorrelateIgnoresTasksKnownBeforeTheDispatch(t *testing.T) {
	e := newEnv(t)
	ref := proxmox.GuestRef{Node: "pve1", Type: proxmox.GuestQEMU, VMID: 100}
	earlier, _, _ := e.client.Power(context.Background(), ref, "stop")
	tasks, err := e.client.Tasks(context.Background(), "pve1", proxmox.TaskFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := proxmox.Want{
		Type: "qmstop", VMID: 100, User: "root@pam!admin",
		From: earlier.StartTime.Add(-1), Until: earlier.StartTime.Add(1),
	}
	if _, result := proxmox.Correlate(tasks, want); result != proxmox.CorrelatedOne {
		t.Fatalf("without a baseline the earlier task correlates: %d", result)
	}
	want.Known = []string{earlier.Raw}
	if _, result := proxmox.Correlate(tasks, want); result != proxmox.CorrelatedNone {
		t.Errorf("a task known before the dispatch must not correlate: %d", result)
	}
}
