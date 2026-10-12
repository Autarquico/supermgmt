package compose

import "testing"

func webExceptions(e ServiceExceptions) Exceptions {
	return Exceptions{Services: map[string]ServiceExceptions{"web": e}}
}

func TestExceptions_CapAdd(t *testing.T) {
	tests := []struct {
		name string
		caps string
		exc  Exceptions
		ok   bool
	}{
		{"approved", "[CHOWN]", webExceptions(ServiceExceptions{CapAdd: []string{"CHOWN"}}), true},
		{"approved subset of several", "[CHOWN, KILL]", webExceptions(ServiceExceptions{CapAdd: []string{"KILL", "CHOWN", "SETUID"}}), true},
		{"no exception", "[CHOWN]", Exceptions{}, false},
		{"one value not approved", "[CHOWN, KILL]", webExceptions(ServiceExceptions{CapAdd: []string{"CHOWN"}}), false},
		{"approved for another service", "[CHOWN]", Exceptions{Services: map[string]ServiceExceptions{"db": {CapAdd: []string{"CHOWN"}}}}, false},
		{"not exemptible even when listed", "[SYS_ADMIN]", webExceptions(ServiceExceptions{CapAdd: []string{"SYS_ADMIN"}}), false},
		{"ALL is not exemptible", "[ALL]", webExceptions(ServiceExceptions{CapAdd: []string{"ALL"}}), false},
		{"case matters", "[chown]", webExceptions(ServiceExceptions{CapAdd: []string{"CHOWN"}}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertException(t, "    cap_add: "+tc.caps+"\n", tc.exc, tc.ok)
		})
	}
}

func TestExceptions_Sysctls(t *testing.T) {
	somaxconn := webExceptions(ServiceExceptions{Sysctls: map[string]string{"net.core.somaxconn": "1024"}})
	tests := []struct {
		name    string
		sysctls string
		exc     Exceptions
		ok      bool
	}{
		{"exact key and value", "{net.core.somaxconn: 1024}", somaxconn, true},
		{"different value", "{net.core.somaxconn: 4096}", somaxconn, false},
		{"unlisted key", "{net.ipv4.ip_forward: 1}", somaxconn, false},
		{"no exception", "{net.core.somaxconn: 1024}", Exceptions{}, false},
		{"outside net. even when listed", "{kernel.shmmax: 1}", webExceptions(ServiceExceptions{Sysctls: map[string]string{"kernel.shmmax": "1"}}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertException(t, "    sysctls: "+tc.sysctls+"\n", tc.exc, tc.ok)
		})
	}
}

func TestExceptions_ExtraHosts(t *testing.T) {
	tests := []struct {
		name  string
		hosts string
		exc   ServiceExceptions
		ok    bool
	}{
		{"colon form approved", `["metrics:10.0.0.9"]`, ServiceExceptions{ExtraHosts: []string{"metrics:10.0.0.9"}}, true},
		{"equals form approved", `["metrics=10.0.0.9"]`, ServiceExceptions{ExtraHosts: []string{"metrics:10.0.0.9"}}, true},
		{"ipv6 approved", `["metrics:fd00::9"]`, ServiceExceptions{ExtraHosts: []string{"metrics=fd00::9"}}, true},
		{"different address", `["metrics:10.0.0.10"]`, ServiceExceptions{ExtraHosts: []string{"metrics:10.0.0.9"}}, false},
		{"different host", `["other:10.0.0.9"]`, ServiceExceptions{ExtraHosts: []string{"metrics:10.0.0.9"}}, false},
		{"no exception", `["metrics:10.0.0.9"]`, ServiceExceptions{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertException(t, "    extra_hosts: "+tc.hosts+"\n", webExceptions(tc.exc), tc.ok)
		})
	}
}

func TestExceptions_ShmSize(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		approved string
		ok       bool
	}{
		{"same notation", "64m", "64m", true},
		{"equivalent notation", "64m", "67108864", true},
		{"upper case unit", "1g", "1GB", true},
		{"larger than approved", "128m", "64m", false},
		{"no exception", "64m", "", false},
		{"unparsable exception", "64m", "lots", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exc := webExceptions(ServiceExceptions{ShmSize: tc.approved})
			assertException(t, "    shm_size: "+tc.model+"\n", exc, tc.ok)
		})
	}
}

func TestExceptions_DoNotLeakAcrossKeys(t *testing.T) {
	exc := webExceptions(ServiceExceptions{CapAdd: []string{"CHOWN"}})
	assertException(t, "    cap_add: [CHOWN]\n    privileged: true\n", exc, false)
}

func assertException(t *testing.T, serviceLines string, exc Exceptions, ok bool) {
	t.Helper()
	err := checkDoc(t, serviceDoc(serviceLines, ""), testTarget(), exc)
	if ok && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		wantRejected(t, err, "")
	}
}

func TestParseByteSize(t *testing.T) {
	tests := map[string]int64{"0": 0, "512": 512, "1b": 1, "2k": 2048, "2KB": 2048, "64m": 64 << 20, "1g": 1 << 30, "3Mb": 3 << 20}
	for in, want := range tests {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "m", "-1", "1x", "1.5m", "lots"} {
		if _, err := parseByteSize(in); err == nil {
			t.Errorf("parseByteSize(%q) succeeded, want error", in)
		}
	}
}
