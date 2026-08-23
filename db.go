// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.

package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const schema = `
CREATE TABLE IF NOT EXISTS bans (
	id SERIAL PRIMARY KEY,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	server TEXT NOT NULL DEFAULT '',
	duration_minutes INTEGER NOT NULL DEFAULT 0,
	reason TEXT NOT NULL DEFAULT '',
	issued_by TEXT NOT NULL,
	raw_notice TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bans_target ON bans (target);
CREATE INDEX IF NOT EXISTS idx_bans_issued_by ON bans (issued_by);
CREATE INDEX IF NOT EXISTS idx_bans_created_at ON bans (created_at DESC);
`

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return db, nil
}

func (b *Bot) recordBan(ev BanEvent, raw string) {
	_, err := b.db.Exec(
		`INSERT INTO bans (action, target, server, duration_minutes, reason, issued_by, raw_notice)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ev.Action, ev.Target, ev.Server, ev.DurationMin, ev.Reason, ev.IssuedBy, raw,
	)
	if err != nil {
		logf("db insert failed: %v", err)
	}
}

// BanRecord is one row as returned to a search, with its DB-assigned id
// and timestamp -- BanEvent itself (parse.go) has neither, since it
// doesn't exist yet at parse time.
type BanRecord struct {
	ID        int
	Action    string
	Target    string
	Server    string
	Duration  int
	Reason    string
	IssuedBy  string
	CreatedAt string
}

// searchBans looks up the most recent matches across target/reason/
// issued_by -- a plain substring ILIKE, not real CIDR-aware IP matching.
// Good enough for "does this nick/host/mask show up anywhere in the
// history" (the common case); a query like "search by CIDR range" would
// need proper inet-typed columns and a <<= comparison instead, not
// implemented here yet.
func (b *Bot) searchBans(query string, limit int) ([]BanRecord, error) {
	rows, err := b.db.Query(
		`SELECT id, action, target, server, duration_minutes, reason, issued_by, created_at
		 FROM bans
		 WHERE target ILIKE '%' || $1 || '%'
		    OR reason ILIKE '%' || $1 || '%'
		    OR issued_by ILIKE '%' || $1 || '%'
		 ORDER BY created_at DESC
		 LIMIT $2`,
		query, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BanRecord
	for rows.Next() {
		var r BanRecord
		if err := rows.Scan(&r.ID, &r.Action, &r.Target, &r.Server, &r.Duration, &r.Reason, &r.IssuedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
