// Package e2e holds the M2 acceptance and security tests (PLAN §9). They drive real processes in
// Docker: a clean Debian host with systemd as PID 1 runs `sm server`, Dex is the identity provider
// on a private docker network, a TLS proxy and a release mirror run in containers of their own, and
// the `sm` of the test machine is the laptop. Nothing is mocked.
//
// The tests carry the build tag e2e (the join test also needs fixtures, for the M1 node image):
//
//	make e2e-server    remote control, local mode, backup/restore, join, secret-leak scans
//	make e2e-install   curl|bash install and the tamper matrix; E2E_DIST=dist serves `make snapshot`
package e2e
