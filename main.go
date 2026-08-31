// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
//
// Cerberus -- ChatNet's ban/kill audit bot, inspired by Libera Chat's
// Beryllia (github.com/Libera-Chat/beryllia). Opers up, requests the
// snomask categories that cover every KLINE/DLINE/XLINE/RESV/KILL on the
// network (solanum's own SNO_GENERAL='s' for the first four,
// SNO_SKILL='k' for KILL -- solanum has no GLINE/ZLINE, those are
// Bahamut/Undernet-era terms from the real 2006 ChatWorld's original
// network, not anything this ircd emits), parses each one (see
// parse.go) and records it in Postgres, then answers !kcheck queries
// against that history.
//
// Services (Atheme OperServ/ChatWorld AKILL) are ordinary privileged
// clients from the ircd's own point of view -- an AKILL produces the
// exact same KLINE snomask notice a human oper's KLINE command would,
// just with the services pseudoclient's name as the issuer. One
// snomask listener therefore already covers every source (Atheme,
// bots, staff) with no special-casing.
package main

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server           string
	Port             string
	Nick             string
	NickservAccount  string
	NickservPassword string
	OperNick         string
	OperPassword     string
	Channel          string
	AdminAccounts    []string
	DatabaseURL      string
}

func loadConfig() Config {
	return Config{
		Server:           getenv("IRC_SERVER", "irc.chatnet.gg"),
		Port:             getenv("IRC_PORT", "6697"),
		Nick:             getenv("CERBERUS_NICK", "Cerberus"),
		NickservAccount:  getenv("CERBERUS_NICKSERV_ACCOUNT", "cerberus"),
		NickservPassword: mustEnv("CERBERUS_NICKSERV_PASSWORD"),
		OperNick:         getenv("CERBERUS_OPER_NICK", "cerberus"),
		OperPassword:     mustEnv("CERBERUS_OPER_PASSWORD"),
		Channel:          getenv("CERBERUS_CHANNEL", "#CN-Bot"),
		AdminAccounts:    splitCommaList(getenv("CERBERUS_ADMIN_ACCOUNTS", "")),
		DatabaseURL:      mustEnv("DATABASE_URL"),
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (cfg Config) isAdmin(account string) bool {
	for _, a := range cfg.AdminAccounts {
		if strings.EqualFold(a, account) {
			return true
		}
	}
	return false
}

// pendingRequest covers every admin command that needs a WHOIS-based
// account check before it runs -- KCHECK originally, JOIN/PART added
// 2026-08-31. `kind` picks which one `finishPending` actually does;
// `query`/`offset` are only meaningful for "kcheck" (the search string
// and page offset), `query` alone (a bare channel name) for "join"/
// "part". One shared struct rather than a union of types since Go has
// no sum types and this bot only ever has ONE request in flight at a
// time anyway (see the 30s staleness check in `startKcheck`/
// `startJoinPart`).
type pendingRequest struct {
	nick      string
	kind      string
	query     string
	offset    int
	createdAt time.Time
}

type Bot struct {
	cfg  Config
	conn net.Conn
	db   *sql.DB

	saslDone bool

	pending *pendingRequest
}

// rejoinExtraChannels replays every JOIN a command persisted (see
// commands.go's finishPending "JOIN" case) -- the bot's own home
// channel is rejoined unconditionally above and never stored here, so
// this only ever touches channels an admin explicitly added.
func (b *Bot) rejoinExtraChannels() {
	channels, err := b.loadExtraChannels()
	if err != nil {
		logf("loading extra channels failed: %v", err)
		return
	}
	for _, ch := range channels {
		b.send("JOIN " + ch)
	}
}

func logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func main() {
	cfg := loadConfig()

	db, err := openDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	b := &Bot{cfg: cfg, db: db}

	backoff := time.Second
	for {
		if err := b.connectAndRun(); err != nil {
			logf("connection error: %v (reconnecting in %s)", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		} else {
			backoff = 60 * time.Second
		}
	}
}

func (b *Bot) connectAndRun() error {
	addr := net.JoinHostPort(b.cfg.Server, b.cfg.Port)
	rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()
	b.conn = tlsConn
	b.pending = nil
	b.saslDone = false

	// SASL PLAIN, pre-registration -- avoids the CHGHOST blip a
	// post-connect NickServ IDENTIFY causes, same as every other bot in
	// this project.
	b.send("CAP LS 302")
	b.send("NICK " + b.cfg.Nick)
	b.send("USER " + b.cfg.Nick + " 0 * :ChatNet ban/kill audit bot")
	logf("connecting to %s as %s", addr, b.cfg.Nick)

	reader := bufio.NewReader(tlsConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		b.dispatch(parseLine(line))
	}
}

func (b *Bot) send(s string) {
	if b.conn == nil {
		return
	}
	b.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(b.conn, "%s\r\n", s)
}

func saslPlainPayload(account, password string) string {
	raw := account + "\x00" + account + "\x00" + password
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func (b *Bot) dispatch(l Line) {
	switch l.Command {
	case "PING":
		b.send("PONG :" + l.Trailing)

	case "CAP":
		if len(l.Params) < 2 {
			break
		}
		switch strings.ToUpper(l.Params[1]) {
		case "LS":
			if strings.Contains(l.Trailing, "sasl") {
				b.send("CAP REQ :sasl")
			} else {
				b.send("CAP END")
			}
		case "ACK":
			if strings.Contains(l.Trailing, "sasl") {
				b.send("AUTHENTICATE PLAIN")
			}
		case "NAK":
			b.send("CAP END")
		}

	case "AUTHENTICATE":
		if len(l.Params) > 0 && l.Params[0] == "+" {
			b.send("AUTHENTICATE " + saslPlainPayload(b.cfg.NickservAccount, b.cfg.NickservPassword))
		}

	case "903": // RPL_SASLSUCCESS
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "904", "905", "906", "907": // SASL failure
		logf("SASL failed (%s: %s) -- connecting unauthenticated", l.Command, l.Trailing)
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "001":
		b.send(fmt.Sprintf("OPER %s %s", b.cfg.OperNick, b.cfg.OperPassword))
		b.send("JOIN " + b.cfg.Channel)
		logf("registered, joined %s, opering up as %s", b.cfg.Channel, b.cfg.OperNick)
		b.rejoinExtraChannels()

	case "381": // RPL_YOUREOPER
		// +s enables server-notice reception; the second parameter is
		// the snomask buffer itself (parsed char-by-char, +/- toggle
		// add/remove) -- "+ks" requests SNO_SKILL (KILL) and
		// SNO_GENERAL (KLINE/DLINE/XLINE/RESV), see this file's own
		// header comment and parse.go's.
		b.send(fmt.Sprintf("MODE %s +s +ks", b.cfg.OperNick))
		logf("oper-up succeeded, requested +s snomask +ks")

	case "464":
		logf("oper-up FAILED (password mismatch) -- won't see any ban/kill notices until this is fixed")

	case "NOTICE":
		b.handleNotice(l)

	case "PRIVMSG":
		if strings.EqualFold(l.target(), b.cfg.Nick) {
			b.handlePrivate(l.Nick, l.text())
		}

	case "330": // RPL_WHOISACCOUNT: <me> <nick> <account> :is logged in as
		if b.pending != nil && len(l.Params) >= 3 && strings.EqualFold(l.Params[1], b.pending.nick) {
			b.finishPending(l.Params[2])
		}

	case "318": // RPL_ENDOFWHOIS -- fallback if 330 never arrived (not identified)
		if b.pending != nil && len(l.Params) >= 2 && strings.EqualFold(l.Params[1], b.pending.nick) {
			b.finishPending("")
		}
	}
}

// handleNotice looks for solanum's own snomask wire format --
// ":<server> NOTICE * :*** Notice -- <text>", literal "*" target, not
// the bot's own nick (confirmed from solanum's sendto_realops_snomask()
// in ircd/send.c) -- and hands the stripped text to parseBanNotice.
// Most SNO_GENERAL/SNO_SKILL traffic isn't a ban/kill at all (remote
// CONNECT notices share SNO_GENERAL too, for one), so a non-match here
// is the normal case, not an error.
func (b *Bot) handleNotice(l Line) {
	if l.target() != "*" {
		return
	}
	const prefix = "*** Notice -- "
	text := l.Trailing
	if !strings.HasPrefix(text, prefix) {
		return
	}
	text = text[len(prefix):]

	ev, ok := parseBanNotice(text)
	if !ok {
		return
	}
	logf("%s: %s by %s -- %s", ev.Action, ev.Target, ev.IssuedBy, ev.Reason)
	b.recordBan(ev, text)
}
