// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
//
// Every input string below is copied verbatim from solanum's own
// sendto_realops_snomask() format strings (solanum-ircd/solanum,
// modules/m_kline.c, modules/m_dline.c, modules/m_xline.c,
// modules/m_resv.c, modules/core/m_kill.c), with placeholder values
// filled in -- not invented text. If a future solanum upgrade changes
// any of this wording, this is the test that should catch it.
package main

import "testing"

func TestParseBanNoticeKline(t *testing.T) {
	cases := []struct {
		name string
		text string
		want BanEvent
	}{
		{"temp remote", "sh is adding a temporary 60 min. K-Line for [*@1.2.3.4] on *.chatnet.gg [flood]",
			BanEvent{Action: "KLINE", Target: "*@1.2.3.4", Server: "*.chatnet.gg", DurationMin: 60, Reason: "flood", IssuedBy: "sh"}},
		{"perm remote", "sh is adding a K-Line for [*@1.2.3.4] on *.chatnet.gg [flood]",
			BanEvent{Action: "KLINE", Target: "*@1.2.3.4", Server: "*.chatnet.gg", Reason: "flood", IssuedBy: "sh"}},
		{"temp local upstream wording", "Sentry added temporary 1440 min. K-Line for [*@5.6.7.8] [message flood detected]",
			BanEvent{Action: "KLINE", Target: "*@5.6.7.8", DurationMin: 1440, Reason: "message flood detected", IssuedBy: "Sentry"}},
		{"temp local global wording (this network's cnircd fork)", "cerbtest1!~cerbtest1@CN-172.32.v.j{admin} added global 1 min. K-Line for [*@cerberustest.example] [cerberus live test kline]",
			BanEvent{Action: "KLINE", Target: "*@cerberustest.example", DurationMin: 1, Reason: "cerberus live test kline", IssuedBy: "cerbtest1!~cerbtest1@CN-172.32.v.j{admin}"}},
		{"perm local", "sh added K-Line for [*@5.6.7.8] [repeat offender]",
			BanEvent{Action: "KLINE", Target: "*@5.6.7.8", Reason: "repeat offender", IssuedBy: "sh"}},
		{"unkline", "sh is removing the K-Line for [*@1.2.3.4] on *.chatnet.gg",
			BanEvent{Action: "UNKLINE", Target: "*@1.2.3.4", Server: "*.chatnet.gg", IssuedBy: "sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseBanNotice(c.text)
			if !ok {
				t.Fatalf("no match for %q", c.text)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParseBanNoticeDline(t *testing.T) {
	cases := []struct {
		name string
		text string
		want BanEvent
	}{
		{"temp", "sh added temporary 60 min. D-Line for [1.2.3.4] [spam]",
			BanEvent{Action: "DLINE", Target: "1.2.3.4", DurationMin: 60, Reason: "spam", IssuedBy: "sh"}},
		{"perm", "sh added D-Line for [1.2.3.4] [spam]",
			BanEvent{Action: "DLINE", Target: "1.2.3.4", Reason: "spam", IssuedBy: "sh"}},
		{"undline temp", "sh has removed the temporary D-Line for: [1.2.3.4]",
			BanEvent{Action: "UNDLINE", Target: "1.2.3.4", IssuedBy: "sh"}},
		{"undline perm", "sh has removed the D-Line for: [1.2.3.4]",
			BanEvent{Action: "UNDLINE", Target: "1.2.3.4", IssuedBy: "sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseBanNotice(c.text)
			if !ok {
				t.Fatalf("no match for %q", c.text)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParseBanNoticeXline(t *testing.T) {
	cases := []struct {
		name string
		text string
		want BanEvent
	}{
		{"temp remote", "sh is adding a temporary 60 min. X-Line for [*sp4mm3r*] on *.chatnet.gg [ad bot]",
			BanEvent{Action: "XLINE", Target: "*sp4mm3r*", Server: "*.chatnet.gg", DurationMin: 60, Reason: "ad bot", IssuedBy: "sh"}},
		{"perm remote", "sh is adding a permanent X-Line for [*sp4mm3r*] on *.chatnet.gg [ad bot]",
			BanEvent{Action: "XLINE", Target: "*sp4mm3r*", Server: "*.chatnet.gg", Reason: "ad bot", IssuedBy: "sh"}},
		{"local perm", "sh added X-Line for [*sp4mm3r*] [ad bot]",
			BanEvent{Action: "XLINE", Target: "*sp4mm3r*", Reason: "ad bot", IssuedBy: "sh"}},
		{"local temp global wording (this network's cnircd fork)", "cerbtest1!~cerbtest1@CN-172.32.v.j{admin} added global 1 min. X-Line for [*cerberusxtest*] [cerberus live test xline]",
			BanEvent{Action: "XLINE", Target: "*cerberusxtest*", DurationMin: 1, Reason: "cerberus live test xline", IssuedBy: "cerbtest1!~cerbtest1@CN-172.32.v.j{admin}"}},
		{"unxline", "sh is removing the X-Line for [*sp4mm3r*] on *.chatnet.gg.",
			BanEvent{Action: "UNXLINE", Target: "*sp4mm3r*", Server: "*.chatnet.gg", IssuedBy: "sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseBanNotice(c.text)
			if !ok {
				t.Fatalf("no match for %q", c.text)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParseBanNoticeResv(t *testing.T) {
	cases := []struct {
		name string
		text string
		want BanEvent
	}{
		{"temp remote", "sh is adding a 60 min. RESV for [K9] on *.chatnet.gg [impersonation]",
			BanEvent{Action: "RESV", Target: "K9", Server: "*.chatnet.gg", DurationMin: 60, Reason: "impersonation", IssuedBy: "sh"}},
		{"perm remote", "sh is adding a permanent RESV for [K9] on *.chatnet.gg [impersonation]",
			BanEvent{Action: "RESV", Target: "K9", Server: "*.chatnet.gg", Reason: "impersonation", IssuedBy: "sh"}},
		{"global temp local", "sh added global 60 min. RESV for [K9] [impersonation]",
			BanEvent{Action: "RESV", Target: "K9", DurationMin: 60, Reason: "impersonation", IssuedBy: "sh"}},
		{"temp local", "sh added temporary 60 min. RESV for [K9] [impersonation]",
			BanEvent{Action: "RESV", Target: "K9", DurationMin: 60, Reason: "impersonation", IssuedBy: "sh"}},
		{"perm local", "sh added RESV for [K9] [impersonation]",
			BanEvent{Action: "RESV", Target: "K9", Reason: "impersonation", IssuedBy: "sh"}},
		{"unresv global", "sh has removed the global RESV for: [K9]",
			BanEvent{Action: "UNRESV", Target: "K9", IssuedBy: "sh"}},
		{"unresv temp", "sh has removed the temporary RESV for: [K9]",
			BanEvent{Action: "UNRESV", Target: "K9", IssuedBy: "sh"}},
		{"unresv plain", "sh has removed the RESV for: [K9]",
			BanEvent{Action: "UNRESV", Target: "K9", IssuedBy: "sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseBanNotice(c.text)
			if !ok {
				t.Fatalf("no match for %q", c.text)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParseBanNoticeKill(t *testing.T) {
	text := "Received KILL message for guest123!~guest@1.2.3.4. From sh (repeat offender)"
	got, ok := parseBanNotice(text)
	if !ok {
		t.Fatalf("no match for %q", text)
	}
	want := BanEvent{Action: "KILL", Target: "guest123!~guest@1.2.3.4", Reason: "(repeat offender)", IssuedBy: "sh"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseBanNoticeNonMatch(t *testing.T) {
	// Ordinary SNO_GENERAL traffic that isn't a ban/kill at all -- must
	// not match anything.
	_, ok := parseBanNotice("Client connecting: guest456 (~guest@1.2.3.4) [1.2.3.4] {clients}")
	if ok {
		t.Fatalf("expected no match for a plain connect notice")
	}
}
