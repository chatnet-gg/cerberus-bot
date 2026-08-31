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

CREATE TABLE IF NOT EXISTS extra_channels (
	channel TEXT PRIMARY KEY
);
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

// addExtraChannel/removeExtraChannel persist the JOIN/PART command's
// effect across reconnects -- the "001" handler replays every row here
// (in addition to the bot's own configured home channel, which is never
// stored here) via loadExtraChannels. ON CONFLICT DO NOTHING makes a
// repeat JOIN of an already-persisted channel a harmless no-op instead
// of a duplicate-key error.
func (b *Bot) addExtraChannel(channel string) error {
	_, err := b.db.Exec(`INSERT INTO extra_channels (channel) VALUES ($1) ON CONFLICT DO NOTHING`, channel)
	return err
}

func (b *Bot) removeExtraChannel(channel string) error {
	_, err := b.db.Exec(`DELETE FROM extra_channels WHERE channel = $1`, channel)
	return err
}

func (b *Bot) loadExtraChannels() ([]string, error) {
	rows, err := b.db.Query(`SELECT channel FROM extra_channels ORDER BY channel`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ch string
		if err := rows.Scan(&ch); err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
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
//
// query == "*" is a special case (K9 ACCESS/LASTCMDS have no equivalent
// of this -- they always list a real access/command scope, never an
// unfiltered dump) meaning "everything, no filter" -- lets an admin
// browse the whole audit trail without already knowing a nick/host/ip to
// search for. offset paginates through it, same -N convention as K9's
// own ACCESS/LASTCMDS (1-based: offset 0 == "-1", the first entry).
func (b *Bot) searchBans(query string, limit, offset int) ([]BanRecord, error) {
	var rows *sql.Rows
	var err error
	if query == "*" {
		rows, err = b.db.Query(
			`SELECT id, action, target, server, duration_minutes, reason, issued_by, created_at
			 FROM bans
			 ORDER BY created_at DESC
			 LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	} else {
		rows, err = b.db.Query(
			`SELECT id, action, target, server, duration_minutes, reason, issued_by, created_at
			 FROM bans
			 WHERE target ILIKE '%' || $1 || '%'
			    OR reason ILIKE '%' || $1 || '%'
			    OR issued_by ILIKE '%' || $1 || '%'
			 ORDER BY created_at DESC
			 LIMIT $2 OFFSET $3`,
			query, limit, offset,
		)
	}
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
