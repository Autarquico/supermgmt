package compose

import (
	"strings"
	"testing"
)

// service wraps a service body (already indented by 4) in a minimal document.
func service(body string) string {
	return "services:\n  web:\n    image: x\n" + body
}

func TestCheckRaw_RejectsSourceForms(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		// Forms the pinned loader would rewrite or drop before any model check.
		{"version", "version: '3'\nservices:\n  web: {image: x}\n", "version"},
		{"short port", service("    ports: ['8080:80']\n"), "services.web.ports[0]"},
		{"port range", service("    ports:\n      - {target: 80, published: '8000-8010', host_ip: 127.0.0.1}\n"), "published"},
		{"port range as target", service("    ports:\n      - {target: '80-81', published: 80, host_ip: 127.0.0.1}\n"), "target"},
		{"port without host_ip", service("    ports:\n      - {target: 80, published: 80}\n"), "host_ip"},
		{"port without published", service("    ports:\n      - {target: 80, host_ip: 127.0.0.1}\n"), "published"},
		{"port out of range", service("    ports:\n      - {target: 80, published: 70000, host_ip: 127.0.0.1}\n"), "outside 1-65535"},
		{"port wildcard host", service("    ports:\n      - {target: 80, published: 80, host_ip: 0.0.0.0}\n"), "neither loopback"},
		{"port foreign host", service("    ports:\n      - {target: 80, published: 80, host_ip: 10.9.9.9}\n"), "neither loopback"},
		{"port ip4in6 loopback", service("    ports:\n      - {target: 80, published: 80, host_ip: '::ffff:127.0.0.1'}\n"), "neither loopback"},
		{"port host_ip not an ip", service("    ports:\n      - {target: 80, published: 80, host_ip: localhost}\n"), "not an IP"},
		{"port unknown field", service("    ports:\n      - {target: 80, published: 80, host_ip: 127.0.0.1, mode: host}\n"), "mode"},
		{"port protocol", service("    ports:\n      - {target: 80, published: 80, host_ip: 127.0.0.1, protocol: sctp}\n"), "sctp"},
		{"string command", service("    command: serve --port 80\n"), "services.web.command"},
		{"string entrypoint", service("    entrypoint: /bin/sh\n"), "services.web.entrypoint"},
		{"list environment", service("    environment: [A=b]\n"), "services.web.environment"},
		{"non-string environment value", service("    environment: {PORT: 80}\n"), "services.web.environment.PORT"},
		{"null environment value", service("    environment: {PASSTHROUGH: }\n"), "services.web.environment.PASSTHROUGH"},
		{"bad environment name", service("    environment: {'A=B': c}\n"), "environment variable name"},
		{"list labels", service("    labels: [a=b]\n"), "services.web.labels"},
		{"missing services", "volumes: {}\n", "services"},
		{"missing image", "services:\n  web: {restart: always}\n", "image"},
		{"bad service name", "services:\n  '../x': {image: x}\n", "service name"},

		// Nested unknown fields.
		{"unknown top-level", "foo: 1\nservices: {}\n", "foo"},
		{"unknown service key", service("    bogus: 1\n"), "services.web.bogus"},
		{"unknown healthcheck key", service("    healthcheck: {test: [CMD, \"true\"], bogus: 1}\n"), "services.web.healthcheck.bogus"},
		{"unknown logging key", service("    logging: {driver: local, bogus: 1}\n"), "services.web.logging.bogus"},
		{"unknown logging option", service("    logging: {driver: local, options: {bogus: 1}}\n"), "services.web.logging.options.bogus"},
		{"unknown deploy key", service("    deploy: {replicas: 3}\n"), "services.web.deploy.replicas"},
		{"unknown deploy resources key", service("    deploy: {resources: {reservations: {}}}\n"), "services.web.deploy.resources.reservations"},
		{"unknown deploy limits key", service("    deploy: {resources: {limits: {devices: []}}}\n"), "services.web.deploy.resources.limits.devices"},
		{"unknown ulimit", service("    ulimits: {core: {soft: 1, hard: 1}}\n"), "services.web.ulimits.core"},
		{"unknown ulimit field", service("    ulimits: {nofile: {soft: 1, hard: 1, max: 2}}\n"), "services.web.ulimits.nofile.max"},
		{"single-value ulimit", service("    ulimits: {nofile: 1024}\n"), "services.web.ulimits.nofile"},
		{"unknown depends_on field", service("    depends_on: {web: {condition: service_started, required: false}}\n"), "required"},
		{"depends_on list form", service("    depends_on: [web]\n"), "services.web.depends_on"},
		{"depends_on unknown service", service("    depends_on: {ghost: {condition: service_started}}\n"), "ghost"},
		{"depends_on condition", service("    depends_on: {web: {condition: always}}\n"), "always"},
		{"unknown network field", "services:\n  web:\n    image: x\n    networks: {n: {ipv4_address: 1.2.3.4}}\nnetworks: {n: {}}\n", "ipv4_address"},
		{"network list form", "services:\n  web:\n    image: x\n    networks: [n]\nnetworks: {n: {}}\n", "services.web.networks"},
		{"undeclared network", service("    networks: {n: {}}\n"), "not declared"},
		{"unknown top-level network key", "services: {}\nnetworks:\n  n: {driver: host}\n", "networks.n.driver"},
		{"unknown top-level volume key", "services: {}\nvolumes:\n  v: {driver: local}\n", "volumes.v.driver"},
		{"top-level volume external", "services: {}\nvolumes:\n  v: {external: true}\n", "volumes.v.external"},
		{"unknown mount field", "services:\n  web:\n    image: x\n    volumes:\n      - {type: volume, source: v, target: /d, consistency: cached}\nvolumes: {v: }\n", "consistency"},
		{"unknown volume option", "services:\n  web:\n    image: x\n    volumes:\n      - {type: volume, source: v, target: /d, volume: {subpath: a}}\nvolumes: {v: }\n", "subpath"},
		{"unknown tmpfs option", service("    volumes:\n      - {type: tmpfs, target: /t, tmpfs: {uid: 1}}\n"), "uid"},

		// Privileged constructs.
		{"privileged", service("    privileged: true\n"), "services.web.privileged"},
		{"network_mode", service("    network_mode: host\n"), "network_mode"},
		{"pid", service("    pid: host\n"), "pid"},
		{"ipc", service("    ipc: host\n"), "ipc"},
		{"devices", service("    devices: ['/dev/sda:/dev/sda']\n"), "devices"},
		{"security_opt", service("    security_opt: [seccomp=unconfined]\n"), "security_opt"},
		{"cap_drop", service("    cap_drop: [ALL]\n"), "cap_drop"},
		{"build", service("    build: .\n"), "build"},
		{"volumes_from", service("    volumes_from: [other]\n"), "volumes_from"},
		{"container_name", service("    container_name: x\n"), "container_name"},
		{"dns", service("    dns: [1.1.1.1]\n"), "dns"},
		{"short volume syntax", service("    volumes: ['/etc:/etc']\n"), "long syntax"},
		{"host bind mount", service("    volumes:\n      - {type: bind, source: /etc, target: /etc}\n"), "bind"},
		{"volume source is a host path", service("    volumes:\n      - {type: volume, source: /etc, target: /etc}\n"), "not declared"},
		{"volume source undeclared", service("    volumes:\n      - {type: volume, source: ghost, target: /d}\n"), "ghost"},
		{"mount target relative", "services:\n  web:\n    image: x\n    volumes:\n      - {type: volume, source: v, target: d}\nvolumes: {v: }\n", "absolute"},
		{"tmpfs with options", service("    tmpfs: ['/tmp:size=64m']\n"), "absolute container path"},
		{"reserved label com.docker", service("    labels: {com.docker.compose.project: x}\n"), "reserved"},
		{"reserved label dev.supermgmt", service("    labels: {dev.supermgmt.owner: x}\n"), "reserved"},
		{"reserved label case", service("    labels: {Dev.SuperMgmt.owner: x}\n"), "reserved"},
		{"reserved label on volume", "services: {}\nvolumes:\n  v:\n    labels: {dev.supermgmt.owner: x}\n", "reserved"},
		{"restart value", service("    restart: sometimes\n"), "sometimes"},
		{"logging driver", service("    logging: {driver: syslog}\n"), "syslog"},

		// Exemptible keys outside their allowlisted values (step 7).
		{"cap_add outside allowlist", service("    cap_add: [SYS_ADMIN]\n"), "SYS_ADMIN"},
		{"cap_add ALL", service("    cap_add: [ALL]\n"), "ALL"},
		{"sysctl outside net.", service("    sysctls: {kernel.core_pattern: x}\n"), "must start with"},
		{"extra_hosts map form", service("    extra_hosts: {a: 1.2.3.4}\n"), "services.web.extra_hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRejected(t, CheckRaw([]byte(tt.doc), testTarget), tt.want)
		})
	}
}

// A construct is rejected no matter how it reaches the service: through an
// anchor, a merge key, or a list of merge keys.
func TestCheckRaw_RejectsPrivilegedConstructsIntroducedByAnchorsAndMerges(t *testing.T) {
	forbidden := []string{
		"privileged: true",
		"network_mode: host",
		"devices: ['/dev/kvm']",
		"cap_add: [SYS_ADMIN]",
		"volumes: [{type: bind, source: /, target: /host}]",
		"ports: [{target: 80, published: 80, host_ip: 0.0.0.0}]",
		"command: run it",
		"environment: [A=b]",
	}
	shapes := map[string]string{
		"merge":      "x-bad: &bad\n  %s\nservices:\n  web:\n    <<: *bad\n    image: x\n",
		"merge list": "x-ok: &ok {restart: always}\nx-bad: &bad\n  %s\nservices:\n  web:\n    <<: [*ok, *bad]\n    image: x\n",
		"alias":      "x-svc: &svc\n  image: x\n  %s\nservices:\n  web: *svc\n",
	}
	for _, f := range forbidden {
		for shape, tmpl := range shapes {
			t.Run(shape+"/"+f, func(t *testing.T) {
				doc := strings.Replace(tmpl, "%s", f, 1)
				err := CheckRaw([]byte(doc), testTarget)
				if err == nil {
					t.Fatalf("accepted:\n%s", doc)
				}
				if strings.Contains(err.Error(), "invalid YAML") {
					t.Fatalf("the fixture itself is not valid YAML: %v", err)
				}
			})
		}
	}
}

func TestCheckRaw_ExplicitKeyOverridesMergedForbiddenValue(t *testing.T) {
	doc := "x-bad: &bad\n  restart: sometimes\nservices:\n  web:\n    <<: *bad\n    image: x\n    restart: always\n"
	if err := CheckRaw([]byte(doc), testTarget); err != nil {
		t.Fatalf("the explicit value replaces the merged one, so the document is valid: %v", err)
	}
}

func TestCheckRaw_AcceptsTheClosedSchema(t *testing.T) {
	doc := `
x-common: &common
  restart: unless-stopped
  logging: {driver: json-file, options: {max-size: 10m, max-file: "3", compress: "true"}}
services:
  web:
    <<: *common
    image: x
    command: ["serve"]
    entrypoint: ["/bin/app"]
    environment: {A: b}
    ports:
      - {target: 80, published: 8080, host_ip: 127.0.0.1}
      - {target: 81, published: 8081, host_ip: "::1", protocol: udp}
      - {target: 82, published: 8082, host_ip: 10.0.0.5}
    expose: [9000]
    healthcheck: {test: [CMD, "true"], interval: 30s, timeout: 5s, retries: 3, start_period: 10s, start_interval: 5s, disable: false}
    depends_on: {db: {condition: service_healthy}}
    volumes:
      - {type: volume, source: data, target: /data, read_only: true, volume: {nocopy: true}}
      - {type: tmpfs, target: /tmp, tmpfs: {size: 67108864, mode: 1777}}
    networks: {default: , backend: {aliases: [api]}}
    labels: {com.acme.team: core}
    user: 1000
    working_dir: /app
    read_only: true
    init: true
    tmpfs: [/run]
    stop_signal: SIGTERM
    stop_grace_period: 30s
    mem_limit: 512m
    cpus: 0.5
    pids_limit: 200
    ulimits: {nofile: {soft: 1024, hard: 2048}, nproc: {soft: 100, hard: 100}}
    deploy: {resources: {limits: {cpus: "0.5", memory: 512M, pids: 100}}}
    cap_add: [NET_BIND_SERVICE]
    sysctls: {net.core.somaxconn: 1024}
    extra_hosts: ["host.docker.internal:host-gateway"]
    shm_size: 64m
    x-note: free-form
  db:
    image: y
volumes:
  data: {labels: {com.acme.kind: state}}
networks:
  backend: {internal: true, labels: {com.acme.kind: net}}
x-anything: [1, 2, {a: b}]
`
	if err := CheckRaw([]byte(doc), testTarget); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRaw_ErrorsCarryPathAndLine(t *testing.T) {
	err := CheckRaw([]byte(service("    privileged: true\n")), testTarget)
	wantRejected(t, err, "services.web.privileged (line 4)")
}
