//go:build stress

// Package stress hammers the concurrency seams of SuperMgmt in process:
// job claim, lease and fencing, the event stream, and the SSH pool.
//
// Run it with the race detector and a high count:
//
//	go test -race -tags stress -count=20 ./test/stress/
//
// The suite is excluded from the default build by the stress tag. Every test
// asserts an invariant that must hold under any interleaving, never a timing.
// Nothing here touches Docker or a real host.
package stress
