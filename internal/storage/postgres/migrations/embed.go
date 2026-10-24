// Package migrations embeds the ordered PostgreSQL migrations.
package migrations

import "embed"

// FS contains the ordered *.sql migration files.
//
//go:embed *.sql
var FS embed.FS
