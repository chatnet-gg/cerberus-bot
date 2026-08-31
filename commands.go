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
	case strings.EqualFold(fields[0], "JOIN"):
		b.startJoinPart(nick, "JOIN", fields[1:])
	case strings.EqualFold(fields[0], "PART"):
		b.startJoinPart(nick, "PART", fields[1:])
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
	"  JOIN <#channel> -- has Cerberus join a channel (e.g. to watch/answer KCHECK somewhere besides its home channel).",
	"  PART <#channel> -- has Cerberus leave a channel. Refuses its own configured home channel -- that's where it lives.",
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

	b.pending = &pendingRequest{nick: nick, kind: "kcheck", query: strings.Join(args, " "), offset: offset, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// startJoinPart mirrors startKcheck's own shape exactly (syntax check,
// one-at-a-time staleness guard, defer to a WHOIS round-trip) -- see
// that function's comments for why the account check can't happen
// synchronously here.
func (b *Bot) startJoinPart(nick, kind string, args []string) {
	if len(args) != 1 || !strings.HasPrefix(args[0], "#") {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: %s <#channel>", nick, kind))
		return
	}
	if b.pending != nil && time.Since(b.pending.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pending = &pendingRequest{nick: nick, kind: kind, query: args[0], createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// finishPending runs once dispatch's "330"/"318" cases resolve the
// requester's NickServ account (or confirm they have none) -- same
// WHOIS-verified-as-admin gate as every other bot in this project (real
// account read authoritatively off the ircd, not trusted from anything
// the sender claimed about themselves). Covers every command kind
// startKcheck/startJoinPart can stage into `b.pending`.
func (b *Bot) finishPending(account string) {
	p := b.pending
	b.pending = nil

	if !b.cfg.isAdmin(account) {
		b.send(fmt.Sprintf("NOTICE %s :Do I know you?", p.nick))
		return
	}

	switch p.kind {
	case "JOIN":
		b.send("JOIN " + p.query)
		b.send(fmt.Sprintf("NOTICE %s :Joined %s.", p.nick, p.query))
		logf("%s had Cerberus JOIN %s", account, p.query)
	case "PART":
		// Refuses the bot's own configured home channel -- that's
		// where it lives (rejoined on every reconnect via the "001"
		// handler regardless), and parting it via this command would
		// just look broken rather than do anything useful: the very
		// next reconnect walks straight back in.
		if strings.EqualFold(p.query, b.cfg.Channel) {
			b.send(fmt.Sprintf("NOTICE %s :Not leaving %s -- that's my home channel.", p.nick, p.query))
			return
		}
		b.send("PART " + p.query)
		b.send(fmt.Sprintf("NOTICE %s :Left %s.", p.nick, p.query))
		logf("%s had Cerberus PART %s", account, p.query)
	case "kcheck":
		b.runKcheck(p)
	}
}

func (b *Bot) runKcheck(p *pendingRequest) {
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
