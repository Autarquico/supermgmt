package app

import (
	"strings"
	"testing"
)

func TestASensitiveKeyLeaksNoByteOfItsValue(t *testing.T) {
	values := []string{"ab,DUMMYSECRET2;DUMMYSECRET3", "first DUMMYSECRET4", ",DUMMYSECRET5", "x&y=DUMMYSECRET6", `a"b'DUMMYSECRET7`, "}DUMMYSECRET8]", "]x"}
	for _, value := range values {
		env := redactedEnv([]string{"POSTGRES_PASSWORD=" + value, "API_TOKEN=" + value})
		labels := redactedLabels(map[string]string{"db.secret": value})
		args := redactedArgs([]string{"--password=" + value, "--api-key=" + value, "DB_PASSWORD=" + value})
		all := strings.Join(append(append(env, args...), labels["db.secret"]), "\n")
		if strings.Contains(all, "DUMMYSECRET") || strings.Contains(all, "]x") {
			t.Errorf("value %q leaked in:\n%s", value, all)
		}
	}
	for _, flag := range []string{"--api_key", "--dsn", "--private-key", "--cookie", "--password"} {
		if got := redactedArgs([]string{flag, "DUMMYSECRET9", "--port", "80"}); strings.Contains(strings.Join(got, " "), "DUMMYSECRET9") || got[3] != "80" {
			t.Errorf("%s leaked or masked too much: %q", flag, got)
		}
	}
	if got := redactedEnv([]string{"MODE=prod a,b"}); got[0] != "MODE=prod a,b" {
		t.Errorf("a harmless key was masked: %q", got)
	}
}

func TestAURLPasswordIsMaskedWithOrWithoutAUser(t *testing.T) {
	for _, url := range []string{"redis://:DUMMYPW@h:6379/0", "rediss://:DUMMYPW@h", "postgres://u:DUMMYPW@h/db"} {
		got := redactedEnv([]string{"CACHE=" + url})[0]
		if strings.Contains(got, "DUMMYPW") || !strings.HasPrefix(got, "CACHE=") {
			t.Errorf("%s -> %s", url, got)
		}
	}
}
