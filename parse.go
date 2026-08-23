// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
//
// Regexes below match solanum's own sendto_realops_snomask() text
// verbatim (checked against solanum-ircd/solanum source, modules/m_kline.c,
// modules/m_dline.c, modules/m_xline.c, modules/m_resv.c,
// modules/core/m_kill.c -- solanum has no GLINE/ZLINE, those are
// Bahamut/Undernet-era terms from the real 2006 ChatWorld's original
// network; the modern equivalents here are KLINE/DLINE/XLINE/RESV/KILL,
// everything solanum itself offers).
//
// Services (Atheme OperServ/ChatWorld AKILL) are ordinary privileged
// clients from the ircd's point of view -- there's no separate ENCAP
// path for a services-issued KLINE, it goes through the exact same
// m_kline.c command handler and produces the exact same snomask notice,
// just with the services pseudoclient's name in place of a human oper's.
// One snomask listener (+s for KLINE/DLINE/XLINE/RESV, +k for KILL)
// therefore already covers every source: Atheme, bots (Sentry,
// cncheck-bot), and staff opers directly -- no per-source special
// casing needed anywhere in this file.
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// BanEvent is one parsed ban/kill action, ready to insert into the bans
// table -- see db.go's schema.
type BanEvent struct {
	Action      string // KLINE, UNKLINE, DLINE, UNDLINE, XLINE, UNXLINE, RESV, UNRESV, KILL
	Target      string // user@host, host, gecos mask, nick mask, or nick!user@host for KILL
	Server      string // explicit "on <server>" target, if any -- empty otherwise
	DurationMin int    // 0 = permanent/not applicable
	Reason      string
	IssuedBy    string
}

type banPattern struct {
	action string
	re     *regexp.Regexp
	// build turns a regex match into a BanEvent; kept as a closure per
	// pattern rather than one shared generic mapper, since group
	// ordering/count genuinely differs across the ~15 real notice
	// shapes below -- explicit per-pattern wiring is easier to verify
	// against the actual solanum source than one clever generic parser
	// would be.
	build func(m []string) BanEvent
}

func atoiOr0(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

var banPatterns = []banPattern{
	// --- KLINE ---
	// "<oper> is adding a temporary <n> min. K-Line for [<user>@<host>] on <server> [<reason>]"
	{"KLINE", regexp.MustCompile(`^(\S+) is adding a temporary (\d+) min\. K-Line for \[([^@\]]+)@([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "KLINE", Target: m[3] + "@" + m[4], Server: m[5], DurationMin: atoiOr0(m[2]), Reason: m[6], IssuedBy: m[1]}
		}},
	// "<oper> is adding a K-Line for [<user>@<host>] on <server> [<reason>]"
	{"KLINE", regexp.MustCompile(`^(\S+) is adding a K-Line for \[([^@\]]+)@([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "KLINE", Target: m[2] + "@" + m[3], Server: m[4], Reason: m[5], IssuedBy: m[1]}
		}},
	// "<oper> added temporary <n> min. K-Line for [<user>@<host>] [<reason>]" (local, no explicit server target)
	{"KLINE", regexp.MustCompile(`^(\S+) added temporary (\d+) min\. K-Line for \[([^@\]]+)@([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "KLINE", Target: m[3] + "@" + m[4], DurationMin: atoiOr0(m[2]), Reason: m[5], IssuedBy: m[1]}
		}},
	// "<oper> added K-Line for [<user>@<host>] [<reason>]" (local, permanent)
	{"KLINE", regexp.MustCompile(`^(\S+) added K-Line for \[([^@\]]+)@([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "KLINE", Target: m[2] + "@" + m[3], Reason: m[4], IssuedBy: m[1]}
		}},
	// "<oper> is removing the K-Line for [<user>@<host>] on <server>"
	{"UNKLINE", regexp.MustCompile(`^(\S+) is removing the K-Line for \[([^@\]]+)@([^\]]+)\] on (\S+)`),
		func(m []string) BanEvent {
			return BanEvent{Action: "UNKLINE", Target: m[2] + "@" + m[3], Server: m[4], IssuedBy: m[1]}
		}},

	// --- DLINE ---
	// "<oper> added temporary <n> min. D-Line for [<host>] [<reason>]"
	{"DLINE", regexp.MustCompile(`^(\S+) added temporary (\d+) min\. D-Line for \[([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "DLINE", Target: m[3], DurationMin: atoiOr0(m[2]), Reason: m[4], IssuedBy: m[1]}
		}},
	// "<oper> added D-Line for [<host>] [<reason>]"
	{"DLINE", regexp.MustCompile(`^(\S+) added D-Line for \[([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "DLINE", Target: m[2], Reason: m[3], IssuedBy: m[1]}
		}},
	// "<oper> has removed the temporary D-Line for: [<host>]" / "...has removed the D-Line for: [<host>]"
	{"UNDLINE", regexp.MustCompile(`^(\S+) has removed the (?:temporary )?D-Line for: \[([^\]]+)\]`),
		func(m []string) BanEvent {
			return BanEvent{Action: "UNDLINE", Target: m[2], IssuedBy: m[1]}
		}},

	// --- XLINE (gecos/realname ban) ---
	// "<oper> is adding a temporary <n> min. X-Line for [<mask>] on <server> [<reason>]"
	{"XLINE", regexp.MustCompile(`^(\S+) is adding a temporary (\d+) min\. X-Line for \[([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "XLINE", Target: m[3], Server: m[4], DurationMin: atoiOr0(m[2]), Reason: m[5], IssuedBy: m[1]}
		}},
	// "<oper> is adding a permanent X-Line for [<mask>] on <server> [<reason>]"
	{"XLINE", regexp.MustCompile(`^(\S+) is adding a permanent X-Line for \[([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "XLINE", Target: m[2], Server: m[3], Reason: m[4], IssuedBy: m[1]}
		}},
	// "<oper> added X-Line for [<mask>] [<reason>]" (local)
	{"XLINE", regexp.MustCompile(`^(\S+) added X-Line for \[([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "XLINE", Target: m[2], Reason: m[3], IssuedBy: m[1]}
		}},
	// "<oper> is removing the X-Line for [<mask>] on <server>." -- note
	// the literal trailing "." with no space before it (confirmed from
	// solanum source); server names/masks contain dots themselves
	// (e.g. "*.chatnet.gg"), so that trailing "." can't be excluded via
	// the character class the way KLINE/UNKLINE's server group is --
	// stripped in the builder below instead.
	{"UNXLINE", regexp.MustCompile(`^(\S+) is removing the X-Line for \[([^\]]+)\] on (.+)$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "UNXLINE", Target: m[2], Server: strings.TrimSuffix(m[3], "."), IssuedBy: m[1]}
		}},

	// --- RESV (nick/channel reservation) ---
	// "<oper> is adding a <n> min. RESV for [<mask>] on <server> [<reason>]"
	{"RESV", regexp.MustCompile(`^(\S+) is adding a (\d+) min\. RESV for \[([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "RESV", Target: m[3], Server: m[4], DurationMin: atoiOr0(m[2]), Reason: m[5], IssuedBy: m[1]}
		}},
	// "<oper> is adding a permanent RESV for [<mask>] on <server> [<reason>]"
	{"RESV", regexp.MustCompile(`^(\S+) is adding a permanent RESV for \[([^\]]+)\] on (\S+) \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "RESV", Target: m[2], Server: m[3], Reason: m[4], IssuedBy: m[1]}
		}},
	// "<oper> added global <n> min. RESV for [<mask>] [<reason>]" / "added temporary <n> min. RESV..." / "added RESV..."
	{"RESV", regexp.MustCompile(`^(\S+) added (?:global |temporary )?(\d+) min\. RESV for \[([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "RESV", Target: m[3], DurationMin: atoiOr0(m[2]), Reason: m[4], IssuedBy: m[1]}
		}},
	{"RESV", regexp.MustCompile(`^(\S+) added RESV for \[([^\]]+)\] \[(.*)\]$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "RESV", Target: m[2], Reason: m[3], IssuedBy: m[1]}
		}},
	// "<oper> has removed the global RESV for: [<mask>]" / "...temporary RESV..." / "...RESV..."
	{"UNRESV", regexp.MustCompile(`^(\S+) has removed the (?:global |temporary )?RESV for: \[([^\]]+)\]`),
		func(m []string) BanEvent {
			return BanEvent{Action: "UNRESV", Target: m[2], IssuedBy: m[1]}
		}},

	// --- KILL ---
	// "Received KILL message for <nick>!<user>@<host>. From <source> Path: <path> (<reason>)" (non-service form)
	{"KILL", regexp.MustCompile(`^Received KILL message for ([^!]+)!([^@]+)@(\S+)\. From (\S+) (.*)$`),
		func(m []string) BanEvent {
			return BanEvent{Action: "KILL", Target: m[1] + "!" + m[2] + "@" + m[3], Reason: m[5], IssuedBy: m[4]}
		}},
}

// parseBanNotice tries every pattern above in order and returns the
// first match, or (BanEvent{}, false) if the notice text isn't one this
// bot knows how to record (most SNO_GENERAL/SNO_SKILL traffic isn't a
// ban/kill at all -- e.g. remote CONNECT notices share SNO_GENERAL too).
func parseBanNotice(text string) (BanEvent, bool) {
	for _, p := range banPatterns {
		if m := p.re.FindStringSubmatch(text); m != nil {
			return p.build(m), true
		}
	}
	return BanEvent{}, false
}
