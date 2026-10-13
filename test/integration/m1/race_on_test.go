//go:build race

package m1

// The race detector slows every operation several-fold; the budgets scale with it.
const raceSlowdown = 10
