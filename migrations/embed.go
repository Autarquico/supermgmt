// Package migrations embeds the forward-only SQL migrations (spec §9, §29.3).
// File names follow NNNNNN_name.up.sql; released files are never edited.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
