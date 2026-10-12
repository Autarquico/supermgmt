package compose

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const testProject = "shop-prod"

const digestRef = "ghcr.io/acme/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testTarget(allowed ...string) Target {
	t := Target{Project: testProject}
	for _, a := range allowed {
		t.AllowedBind = append(t.AllowedBind, netip.MustParseAddr(a))
	}
	return t
}

// serviceDoc wraps service-level YAML lines (already 4-space indented) and
// optional top-level sections in a complete document with services web and db.
func serviceDoc(webLines, topLevel string) string {
	return "services:\n  web:\n    image: " + digestRef + "\n" + webLines +
		"  db:\n    image: " + digestRef + "\n" + topLevel
}

// checkDoc loads doc and runs the model pass; a document the loader itself
// refuses fails the test, so rejection cases really exercise CheckModel.
func checkDoc(t *testing.T, doc string, target Target, exceptions Exceptions) error {
	t.Helper()
	p, err := Load([]byte(doc), target.Project)
	if err != nil {
		t.Fatalf("loader refused the document: %v", err)
	}
	return CheckModel(p, target, exceptions)
}

func wantRejected(t *testing.T, err error, pathPart string) {
	t.Helper()
	if !errors.Is(err, smerr.FromReason(smerr.ReasonComposeRejected, "")) {
		t.Fatalf("error = %v, want COMPOSE_REJECTED", err)
	}
	if pathPart != "" && !strings.Contains(err.Error(), pathPart) {
		t.Fatalf("error = %q, want it to name %q", err, pathPart)
	}
}

const fullService = `    command: ["serve", "--port=8080"]
    entrypoint: ["/app"]
    environment: {MODE: prod, EMPTY: ""}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1, protocol: tcp}
      - {target: 53, published: 5353, host_ip: "::1", protocol: udp}
    expose: [9000]
    healthcheck: {test: ["CMD", "true"], interval: 5s, timeout: 2s, retries: 3, start_period: 10s, start_interval: 1s}
    restart: unless-stopped
    depends_on: {db: {condition: service_healthy}}
    volumes:
      - {type: volume, source: data, target: /data, read_only: false, volume: {nocopy: true}}
      - {type: tmpfs, target: /scratch, tmpfs: {size: 1000, mode: 1777}}
    networks: {backend: {aliases: [web-internal]}}
    labels: {team: shop}
    logging: {driver: json-file, options: {max-size: 10m, max-file: "3"}}
    user: "1000:1000"
    working_dir: /app
    read_only: true
    init: true
    tmpfs: [/run]
    stop_signal: SIGINT
    stop_grace_period: 20s
    mem_limit: 256m
    cpus: 0.5
    pids_limit: 200
    ulimits: {nofile: {soft: 1024, hard: 2048}}
    deploy: {resources: {limits: {cpus: "0.5", memory: 256M, pids: 200}}}
    x-note: {anything: [1, 2]}
`

const fullTopLevel = `volumes:
  data: {labels: {team: shop}}
networks:
  backend: {internal: true, labels: {team: shop}}
x-shared: {anything: true}
`

func TestCheckModel_AcceptsEveryAllowlistedKey(t *testing.T) {
	if err := checkDoc(t, serviceDoc(fullService, fullTopLevel), testTarget(), Exceptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckModel_AcceptsLoaderDefaults(t *testing.T) {
	// No networks, volumes, ports or depends_on: the loader adds the default
	// network, null command/entrypoint and the project name.
	if err := checkDoc(t, serviceDoc("", ""), testTarget(), Exceptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckModel_RejectsDeniedServiceKeys(t *testing.T) {
	tests := map[string]string{
		"privileged":       "    privileged: true\n",
		"cap_add":          "    cap_add: [NET_ADMIN]\n",
		"cap_drop":         "    cap_drop: [ALL]\n",
		"security_opt":     "    security_opt: [seccomp=unconfined]\n",
		"network_mode":     "    network_mode: host\n",
		"pid":              "    pid: host\n",
		"ipc":              "    ipc: host\n",
		"userns_mode":      "    userns_mode: host\n",
		"uts":              "    uts: host\n",
		"devices":          "    devices: [\"/dev/kvm:/dev/kvm\"]\n",
		"gpus":             "    gpus: all\n",
		"cgroup_parent":    "    cgroup_parent: /x\n",
		"cgroup":           "    cgroup: host\n",
		"sysctls":          "    sysctls: {net.core.somaxconn: 1}\n",
		"extra_hosts":      "    extra_hosts: [\"h:1.2.3.4\"]\n",
		"dns":              "    dns: [1.1.1.1]\n",
		"dns_opt":          "    dns_opt: [ndots:1]\n",
		"dns_search":       "    dns_search: [example.com]\n",
		"container_name":   "    container_name: fixed\n",
		"hostname":         "    hostname: fixed\n",
		"links":            "    links: [db]\n",
		"volumes_from":     "    volumes_from: [db]\n",
		"build":            "    build: {context: .}\n",
		"platform":         "    platform: linux/amd64\n",
		"profiles":         "    profiles: [debug]\n",
		"runtime":          "    runtime: runc\n",
		"storage_opt":      "    storage_opt: {size: 1G}\n",
		"oom_kill_disable": "    oom_kill_disable: true\n",
		"oom_score_adj":    "    oom_score_adj: -500\n",
		"shm_size":         "    shm_size: 64m\n",
		"env_file":         "    env_file: [/etc/shadow]\n",
		"pull_policy":      "    pull_policy: always\n",
		"stdin_open":       "    stdin_open: true\n",
		"tty":              "    tty: true\n",
		"scale":            "    scale: 3\n",
		"mem_swappiness":   "    mem_swappiness: 10\n",
		"deploy replicas":  "    deploy: {replicas: 3}\n",
		"deploy reserv.":   "    deploy: {resources: {reservations: {memory: 1M}}}\n",
		"network extra":    "    networks: {backend: {ipv4_address: 10.0.0.2}}\n",
		"port extra":       "    ports: [{target: 80, published: 80, host_ip: 127.0.0.1, name: web}]\n",
	}
	top := "networks:\n  backend: {}\n"
	for name, lines := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkDoc(t, serviceDoc(lines, top), testTarget(), Exceptions{})
			wantRejected(t, err, "")
		})
	}
}

func TestCheckModel_NamesTheOffendingPath(t *testing.T) {
	err := checkDoc(t, serviceDoc("    deploy: {replicas: 3}\n", ""), testTarget(), Exceptions{})
	wantRejected(t, err, "services.web.deploy.replicas")
}

func TestCheckModel_RejectsUnknownLoaderFields(t *testing.T) {
	// Simulates a compose-go release that starts emitting a field of its own.
	p, err := Load([]byte(serviceDoc("", "")), testProject)
	if err != nil {
		t.Fatal(err)
	}
	web := p.Services["web"]
	web.Hostname = "introduced-by-loader"
	p.Services["web"] = web
	wantRejected(t, CheckModel(p, testTarget(), Exceptions{}), "services.web.hostname")
}

func TestCheckModel_RejectsForeignProjectName(t *testing.T) {
	p, err := Load([]byte(serviceDoc("", "")), "other")
	if err != nil {
		t.Fatal(err)
	}
	wantRejected(t, CheckModel(p, testTarget(), Exceptions{}), "name")
}

func TestCheckModel_ServiceValues(t *testing.T) {
	tests := map[string]string{
		"restart on-failure":     "    restart: on-failure:3\n",
		"logging syslog":         "    logging: {driver: syslog}\n",
		"depends_on false":       "    depends_on: {db: {condition: service_started, required: false}}\n",
		"depends_on restart":     "    depends_on: {db: {condition: service_started, restart: true}}\n",
		"label com.docker":       "    labels: {com.docker.compose.project: x}\n",
		"label dev.supermgmt":    "    labels: {dev.supermgmt.owner: x}\n",
		"environment null":       "    environment: {TOKEN: }\n",
		"relative tmpfs":         "    tmpfs: [scratch]\n",
		"ulimit core":            "    ulimits: {core: {soft: 1, hard: 1}}\n",
		"ulimit scalar":          "    ulimits: {nofile: 1024}\n",
		"volume bind":            "    volumes: [{type: bind, source: /etc, target: /host-etc}]\n",
		"volume tmpfs w/ source": "    volumes: [{type: tmpfs, source: data, target: /d}]\n",
		"volume named w/ tmpfs":  "    volumes: [{type: volume, source: data, target: /d, tmpfs: {size: 1}}]\n",
		"volume bind options":    "    volumes: [{type: volume, source: data, target: /d, bind: {propagation: shared}}]\n",
		"volume relative target": "    volumes: [{type: volume, source: data, target: d}]\n",
	}
	top := "volumes:\n  data: {}\nnetworks:\n  backend: {}\n"
	for name, lines := range tests {
		t.Run(name, func(t *testing.T) {
			wantRejected(t, checkDoc(t, serviceDoc(lines, top), testTarget(), Exceptions{}), "")
		})
	}
}

func TestCheckModel_Ports(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		allowed []string
		ok      bool
	}{
		{"ipv4 loopback", "{target: 80, published: 8080, host_ip: 127.0.0.1}", nil, true},
		{"ipv6 loopback", "{target: 80, published: 8080, host_ip: \"::1\"}", nil, true},
		{"allowed bind address", "{target: 80, published: 8080, host_ip: 10.0.0.5}", []string{"10.0.0.5"}, true},
		{"allowed bind address of another target", "{target: 80, published: 8080, host_ip: 10.0.0.5}", []string{"10.0.0.6"}, false},
		{"wildcard", "{target: 80, published: 8080, host_ip: 0.0.0.0}", []string{"10.0.0.5"}, false},
		{"wildcard v6", "{target: 80, published: 8080, host_ip: \"::\"}", nil, false},
		{"missing host_ip", "{target: 80, published: 8080}", nil, false},
		{"missing published", "{target: 80, host_ip: 127.0.0.1}", nil, false},
		{"host mode", "{target: 80, published: 8080, host_ip: 127.0.0.1, mode: host}", nil, false},
		{"published range", "{target: 80, published: \"8080-8081\", host_ip: 127.0.0.1}", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDoc(t, serviceDoc("    ports: ["+tc.port+"]\n", ""), testTarget(tc.allowed...), Exceptions{})
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok {
				wantRejected(t, err, "ports")
			}
		})
	}
}

func TestCheckModel_PortPolicyIsPerTarget(t *testing.T) {
	doc := serviceDoc("    ports: [{target: 80, published: 8080, host_ip: 10.0.0.5}]\n", "")
	if err := checkDoc(t, doc, testTarget("10.0.0.5"), Exceptions{}); err != nil {
		t.Fatalf("target allowing 10.0.0.5: %v", err)
	}
	wantRejected(t, checkDoc(t, doc, testTarget(), Exceptions{}), "ports")
}

func TestCheckModel_TopLevelResources(t *testing.T) {
	tests := map[string]string{
		"external volume":    "volumes:\n  data: {external: true}\n",
		"named volume":       "volumes:\n  data: {name: other_project_data}\n",
		"volume driver":      "volumes:\n  data: {driver: local, driver_opts: {type: nfs}}\n",
		"external network":   "networks:\n  backend: {external: true}\n",
		"named network":      "networks:\n  backend: {name: host}\n",
		"network driver":     "networks:\n  backend: {driver: macvlan}\n",
		"network attachable": "networks:\n  backend: {attachable: true}\n",
		"network ipam":       "networks:\n  backend: {ipam: {driver: default}}\n",
	}
	for name, top := range tests {
		t.Run(name, func(t *testing.T) {
			wantRejected(t, checkDoc(t, serviceDoc("", top), testTarget(), Exceptions{}), "")
		})
	}
}

func TestCheckModel_ProjectPrefixedResourceNameIsTheOnlyAllowedName(t *testing.T) {
	top := "volumes:\n  data: {name: " + testProject + "_data}\n"
	if err := checkDoc(t, serviceDoc("", top), testTarget(), Exceptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckModel_RequiresAService(t *testing.T) {
	p, err := Load([]byte(serviceDoc("", "")), testProject)
	if err != nil {
		t.Fatal(err)
	}
	clear(p.Services)
	wantRejected(t, CheckModel(p, testTarget(), Exceptions{}), "services")
}
