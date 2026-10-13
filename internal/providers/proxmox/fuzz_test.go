package proxmox

import "testing"

const validUPIDFuzzSeed = "UPID:pve1:0000A1B2:0123ABCD:65A1B2C3:qmstart:100:sm@pve!tok:"

func FuzzParseUPID(f *testing.F) {
	f.Add(validUPIDFuzzSeed)
	f.Add("UPID:pve1:+1:2:3:qmstart:100:u:")
	f.Add("UPID:a:b:c:d:e:f:g:")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseUPID(s)
		if err != nil {
			return
		}
		if u.Raw != s || !nodeNamePattern.MatchString(u.Node) || !taskTypePattern.MatchString(u.Type) || u.User == "" {
			t.Fatalf("accepted UPID %q violates its own grammar: %+v", s, u)
		}
		if u.PID < 0 || u.PStart < 0 {
			t.Fatalf("negative field in %+v", u)
		}
	})
}

func FuzzParseUPIDAnswer(f *testing.F) {
	f.Add([]byte(`{"data":"` + validUPIDFuzzSeed + `"}`))
	f.Add([]byte(`{"data":null}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, body []byte) {
		u, err := parseUPIDAnswer(body)
		if err == nil && u.Raw == "" {
			t.Fatal("accepted an answer without a task id")
		}
	})
}

func FuzzDecodeInventory(f *testing.F) {
	f.Add([]byte(`[{"type":"node","node":"pve1","status":"online","maxcpu":8,"maxmem":1024,"uptime":5},` +
		`{"type":"qemu","vmid":100,"node":"pve1","name":"vm","status":"running","template":0},` +
		`{"type":"storage","storage":"local","node":"pve1","content":"iso,backup","shared":1}]`))
	f.Add([]byte(`[{"type":"qemu","vmid":-1,"node":"pve1"}]`))
	f.Add([]byte(`[{"type":"node","node":"bad name"}]`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		inv, err := decodeInventory(data)
		if err != nil {
			return
		}
		if len(inv.Nodes)+len(inv.Guests)+len(inv.Storages) > len(data) {
			t.Fatal("more resources than input bytes")
		}
		for _, g := range inv.Guests {
			if g.Ref.VMID <= 0 || !nodeNamePattern.MatchString(g.Ref.Node) {
				t.Fatalf("accepted guest without a valid identity: %+v", g.Ref)
			}
		}
		for _, n := range inv.Nodes {
			if !nodeNamePattern.MatchString(n.Name) {
				t.Fatalf("accepted node name %q", n.Name)
			}
		}
	})
}

func FuzzDecodePathPrivileges(f *testing.F) {
	f.Add("/", []byte(`{"/":{"Sys.Audit":1,"VM.Audit":0}}`))
	f.Add("/vms/100", []byte(`{"/":{"Sys.Audit":1}}`))
	f.Add("/", []byte(`{"/":{"Sys.Audit":"x"}}`))
	f.Add("", []byte(`null`))
	f.Fuzz(func(t *testing.T, path string, data []byte) {
		privs, err := decodePathPrivileges(path, data)
		if err == nil && privs == nil {
			t.Fatal("success must return a non-nil (possibly empty) set")
		}
	})
}

func FuzzDecodeTaskStatus(f *testing.F) {
	u, err := ParseUPID(validUPIDFuzzSeed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"status":"running"}`))
	f.Add([]byte(`{"status":"stopped","exitstatus":"OK"}`))
	f.Add([]byte(`{"status":"stopped"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := decodeTaskStatus(u, data)
		if err != nil {
			return
		}
		if st.Status != "running" && (st.Status != "stopped" || st.ExitStatus == "") {
			t.Fatalf("accepted undecided status %+v", st)
		}
	})
}

func FuzzDecodeTaskList(f *testing.F) {
	f.Add([]byte(`[{"upid":"` + validUPIDFuzzSeed + `","status":"OK"},{"upid":"UPID:bad"},{"upid":"` + validUPIDFuzzSeed + `"}]`))
	f.Add([]byte(`[{}]`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		tasks, rows, err := decodeTaskList(data)
		if err != nil {
			return
		}
		if len(tasks) > rows || rows > len(data) {
			t.Fatalf("%d tasks from %d rows in %d bytes", len(tasks), rows, len(data))
		}
	})
}

func FuzzParsePVEError(f *testing.F) {
	f.Add([]byte(`{"message":"no","errors":{"vmid":"bad"}}`))
	f.Add([]byte(`{"message":"  "}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, body []byte) {
		e, ok := parsePVEError(body)
		if ok && e.Message == "" && len(e.Errors) == 0 {
			t.Fatal("reported an error document with neither message nor errors")
		}
		if isPVEError(body) != ok {
			t.Fatal("isPVEError disagrees with parsePVEError")
		}
	})
}
