// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.

package main

import (
	"fmt"
	"regexp"
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
	"  KCHECK * -- list the whole audit trail, most recent first, when you have nothing specific to search for.",
	"  KCHECK <query> -N -- page through the results starting at entry N (1-based), e.g. KCHECK * -11 for the second page.",
	"  JOIN <#channel> -- have Cerberus join a channel, for instance to answer KCHECK somewhere besides its home channel. Remembered: it rejoins after a reconnect.",
	"  PART <#channel> -- have Cerberus leave a channel and forget it. It refuses to leave its own home channel.",
	"  HELP -- this message.",
}

func (b *Bot) handleHelp(nick string) {
	for _, line := range helpLines {
		b.send(fmt.Sprintf("NOTICE %s :%s", nick, line))
	}
}

// splitPageArg takes a trailing "-N" (N >= 1) off the arguments and returns
// the entries to skip for it: "-11" starts at the 11th entry, so it skips 10.
// Anything else, including a lone "-0", stays part of the query.
func splitPageArg(args []string) ([]string, int) {
	if n := len(args); n > 0 {
		if v, err := strconv.Atoi(args[n-1]); err == nil && v < 0 {
			return args[:n-1], -v - 1
		}
	}
	return args, 0
}

// nextPageHint is the line that tells how to continue: only a full page can
// have more entries after it.
func nextPageHint(query string, offset, shown int) string {
	if shown < kcheckResultLimit {
		return ""
	}
	return fmt.Sprintf("For next set of entries enter: KCHECK %s -%d", query, offset+kcheckResultLimit+1)
}

func (b *Bot) startKcheck(nick string, args []string) {
	args, offset := splitPageArg(args)
	if len(args) == 0 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: KCHECK <nick|host|ip|mask|text|*> [-N]", nick))
		return
	}
	if b.pending != nil && time.Since(b.pending.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pending = &pendingRequest{nick: nick, kind: "kcheck", query: strings.Join(args, " "), offset: offset, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// finishKcheck runs once dispatch's "330"/"318" cases resolve the
// requester's NickServ account (or confirm they have none) -- same
// WHOIS-verified-as-admin gate as every other bot in this project (real
// account read authoritatively off the ircd, not trusted from anything
// the sender claimed about themselves).
// channelNameRe is what JOIN/PART accept: a # channel, no spaces, commas
// (which would be several channels) or bell characters.
var channelNameRe = regexp.MustCompile(`^#[^\s,\x07]{1,49}$`)

func (b *Bot) startJoinPart(nick, kind string, args []string) {
	if len(args) != 1 || !channelNameRe.MatchString(args[0]) {
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
		if err := b.addExtraChannel(p.query); err != nil {
			logf("remembering JOIN %s failed: %v", p.query, err)
		}
		b.send(fmt.Sprintf("NOTICE %s :Joined %s (remembered: I rejoin it after a reconnect).", p.nick, p.query))
		logf("%s had Cerberus JOIN %s", account, p.query)
	case "PART":
		// The home channel is rejoined on every connect anyway, so leaving
		// it here would only look broken.
		if strings.EqualFold(p.query, b.cfg.Channel) {
			b.send(fmt.Sprintf("NOTICE %s :Not leaving %s -- that is my home channel.", p.nick, p.query))
			return
		}
		b.send("PART " + p.query)
		if err := b.removeExtraChannel(p.query); err != nil {
			logf("forgetting PART %s failed: %v", p.query, err)
		}
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
	if hint := nextPageHint(p.query, p.offset, len(records)); hint != "" {
		b.send(fmt.Sprintf("NOTICE %s :%s", p.nick, hint))
	}
}
