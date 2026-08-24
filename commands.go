// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const kcheckResultLimit = 10

func (b *Bot) handlePrivate(nick, text string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	switch {
	case strings.EqualFold(fields[0], "KCHECK"):
		b.startKcheck(nick, fields[1:])
	case strings.EqualFold(fields[0], "HELP"):
		b.handleHelp(nick)
	}
}

var helpLines = []string{
	"Cerberus -- ChatNet's ban/kill audit bot. Records every KLINE/DLINE/XLINE/RESV/KILL on the network (any source: Atheme, bots, staff) and makes them searchable.",
	"Commands (all via /msg Cerberus <command>, admin-only, WHOIS-verified):",
	"  KCHECK <query> -- search recorded bans/kills by nick, host, IP, mask, reason, or issuing oper (substring match).",
	"  KCHECK * -- list the whole audit trail, most recent first, when you don't have a nick/host/ip to search for.",
	"  KCHECK <query> -N -- page through results starting at entry N (1-based), same convention as K9's ACCESS/LASTCMDS.",
	"  HELP -- this message.",
}

func (b *Bot) handleHelp(nick string) {
	for _, line := range helpLines {
		b.send(fmt.Sprintf("NOTICE %s :%s", nick, line))
	}
}

func (b *Bot) startKcheck(nick string, args []string) {
	if len(args) == 0 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: KCHECK <nick|host|ip|mask|text|*>", nick))
		return
	}
	if b.pending != nil && time.Since(b.pending.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}

	// Trailing "-N" page offset, same convention as K9's ACCESS/
	// LASTCMDS (1-based: "-11" starts at the 11th match). Only stripped
	// when it's actually a negative integer, so a query that happens to
	// end in "-something" non-numeric (e.g. a hostname) isn't mangled.
	offset := 0
	if n := len(args); n > 0 {
		if v, err := strconv.Atoi(args[n-1]); err == nil && v < 0 {
			offset = -v - 1
			if offset < 0 {
				offset = 0
			}
			args = args[:n-1]
		}
	}
	if len(args) == 0 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: KCHECK <nick|host|ip|mask|text|*>", nick))
		return
	}

	b.pending = &pendingKcheck{nick: nick, query: strings.Join(args, " "), offset: offset, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// finishKcheck runs once dispatch's "330"/"318" cases resolve the
// requester's NickServ account (or confirm they have none) -- same
// WHOIS-verified-as-admin gate as every other bot in this project (real
// account read authoritatively off the ircd, not trusted from anything
// the sender claimed about themselves).
func (b *Bot) finishKcheck(account string) {
	p := b.pending
	b.pending = nil

	if !b.cfg.isAdmin(account) {
		b.send(fmt.Sprintf("NOTICE %s :Do I know you?", p.nick))
		return
	}

	records, err := b.searchBans(p.query, kcheckResultLimit, p.offset)
	if err != nil {
		logf("kcheck query failed: %v", err)
		b.send(fmt.Sprintf("NOTICE %s :Search failed, check the logs.", p.nick))
		return
	}
	if len(records) == 0 {
		if p.offset > 0 {
			b.send(fmt.Sprintf("NOTICE %s :No more matches for %q past entry %d.", p.nick, p.query, p.offset))
		} else {
			b.send(fmt.Sprintf("NOTICE %s :No matches for %q.", p.nick, p.query))
		}
		return
	}

	label := fmt.Sprintf("%d match(es) for %q", len(records), p.query)
	if p.offset > 0 {
		label = fmt.Sprintf("%s, starting at #%d", label, p.offset+1)
	}
	b.send(fmt.Sprintf("NOTICE %s :%s (most recent first):", p.nick, label))
	for _, r := range records {
		dur := "permanent"
		if r.Duration > 0 {
			dur = fmt.Sprintf("%d min", r.Duration)
		}
		b.send(fmt.Sprintf("NOTICE %s :[#%d] %s %s (%s) by %s at %s -- %s",
			p.nick, r.ID, r.Action, r.Target, dur, r.IssuedBy, r.CreatedAt, r.Reason))
	}

	// Page might not be full, same "don't dump everything at once"
	// philosophy as K9's ACCESS/LASTCMDS -- if it IS full, there could
	// be more, so tell them how to page forward instead of silently
	// stopping at kcheckResultLimit.
	if len(records) == kcheckResultLimit {
		nextStart := p.offset + kcheckResultLimit + 1
		b.send(fmt.Sprintf("NOTICE %s :For next set of entries enter: KCHECK %s -%d", p.nick, p.query, nextStart))
	}
}
