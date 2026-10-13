package compose

import (
	"errors"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const loadSample = `
services:
  web:
    image: ghcr.io/acme/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    command: ["serve", "--price=$$5"]
    environment:
      GREETING: "${HOME}"
`

func TestLoad_ParsesInterpolatedDocument(t *testing.T) {
	p, err := Load([]byte(loadSample), "shop-prod")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "shop-prod" {
		t.Errorf("project name = %q, want shop-prod", p.Name)
	}
	web := p.Services["web"]
	if got := web.Command[1]; got != "--price=$$5" {
		t.Errorf("command arg = %q: the loader must not interpolate", got)
	}
	if got := *web.Environment["GREETING"]; got != "${HOME}" {
		t.Errorf("environment = %q: the loader must not read the process environment", got)
	}
}

func TestLoad_ProjectNameIsImperative(t *testing.T) {
	p, err := Load([]byte("name: other\n"+loadSample), "shop-prod")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "shop-prod" {
		t.Errorf("project name = %q, want the caller's shop-prod", p.Name)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := map[string]string{
		"not yaml":              "services: [",
		"schema violation":      "services:\n  web:\n    image: x\n    ports: nope\n",
		"unknown service key":   "services:\n  web:\n    image: x\n    nope: 1\n",
		"service without image": "services:\n  web: {}\n",
		"undefined secret":      "services:\n  web:\n    image: x\n    secrets: [token]\n",
		"undefined config":      "services:\n  web:\n    image: x\n    configs: [conf]\n",
		"undefined network":     "services:\n  web:\n    image: x\n    networks: [elsewhere]\n",
		"undefined volume":      "services:\n  web:\n    image: x\n    volumes: [{type: volume, source: nowhere, target: /d}]\n",
		"healthcheck extra key": "services:\n  web:\n    image: x\n    healthcheck: {test: [CMD, 'true'], nope: 1}\n",
		"logging extra key":     "services:\n  web:\n    image: x\n    logging: {driver: json-file, nope: 1}\n",
		"volume without type":   "services:\n  web:\n    image: x\n    volumes: [{source: data, target: /d}]\nvolumes:\n  data: {}\n",
		"hostname host_ip":      "services:\n  web:\n    image: x\n    ports: [{target: 80, published: 80, host_ip: localhost}]\n",
		"oversized":             "# " + strings.Repeat("x", MaxRawBytes) + "\n" + loadSample,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(doc), "shop-prod")
			if !errors.Is(err, smerr.FromReason(smerr.ReasonComposeRejected, "")) {
				t.Fatalf("Load error = %v, want COMPOSE_REJECTED", err)
			}
		})
	}
}

func TestLoad_ReadsNoFiles(t *testing.T) {
	doc := "services:\n  web:\n    image: x\n    env_file: [/etc/hostname]\n"
	p, err := Load([]byte(doc), "shop-prod")
	if err != nil {
		return // refusing outright is also safe
	}
	if env := p.Services["web"].Environment; len(env) != 0 {
		t.Errorf("env_file was resolved into environment: %v", env)
	}
}
