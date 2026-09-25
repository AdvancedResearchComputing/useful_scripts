package main

import (
	"fmt"
	"io"
	"log/syslog"
	"sort"
	"strings"
	"time"
)

// auditor writes one key=value line per decision to syslog, for Splunk, and
// mirrors it to stderr for whatever invoked us. The jti is the join key: the
// same value is on ColdFront's mint line, and the two events happen on hosts
// that never talk to each other. Without both halves nobody can answer "was
// this repair authorized, and did it run?"
type auditor struct {
	sys    *syslog.Writer
	mirror io.Writer
}

func newAuditor(mirror io.Writer) *auditor {
	a := &auditor{mirror: mirror}
	// No syslog is not fatal -- the invoking service still sees stderr -- but
	// it is worth one line, because a host that is not forwarding is exactly
	// the deployment gap the design warns about.
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "fix-project-perms")
	if err != nil {
		fmt.Fprintf(mirror, "warning: syslog unavailable (%v); audit lines go to stderr only\n", err)
		return a
	}
	a.sys = w
	return a
}

func (a *auditor) line(decision string, fields map[string]any) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{"fix-project-perms decision=" + decision}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	return strings.Join(parts, " ")
}

// granted and denied are logged with the same fidelity. A stream of denials
// for one subject is the probing signal, and it is only visible if refusals
// are indexed alongside successes.
func (a *auditor) info(decision string, fields map[string]any) {
	l := a.line(decision, fields)
	if a.sys != nil {
		_ = a.sys.Info(l)
	}
	fmt.Fprintln(a.mirror, l)
}

func (a *auditor) warn(decision string, fields map[string]any) {
	l := a.line(decision, fields)
	if a.sys != nil {
		_ = a.sys.Warning(l)
	}
	fmt.Fprintln(a.mirror, l)
}

func (a *auditor) close() {
	if a.sys != nil {
		_ = a.sys.Close()
	}
}

func since(t time.Time) string {
	return time.Since(t).Round(time.Millisecond).String()
}
