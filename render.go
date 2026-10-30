package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// output prints a module result as styled plain text. Results are never shown
// as raw JSON: maps become aligned key/value blocks and WHOIS bodies keep their
// classic record layout.
func output(label string, v any) {
	section(label)
	switch x := v.(type) {
	case nil:
		fmt.Println("  " + paint(cDim, "no data"))
	case Result:
		renderResult(x)
	case *Result:
		renderResult(*x)
	case map[string]any:
		renderMap(x, 1)
	default:
		renderAny(x, 1)
	}
}

func section(label string) {
	fmt.Println()
	fmt.Println("  " + paint(cCyan, "◆ ") + paint(cBold+cFg, strings.ToUpper(label)))
	fmt.Println("  " + paint(cDim, strings.Repeat("─", 58)))
}

func kvLine(indent int, key, value string) {
	if value == "" {
		return
	}
	pad := strings.Repeat("  ", indent)
	fmt.Println(pad + paint(cCyan, fmt.Sprintf("%-10s", key)) + paint(cFg, value))
}

func renderResult(r Result) {
	fmt.Println("  " + paint(cDim, "target"))
	kvLine(2, "domain", r.Domain)
	kvLine(2, "protocol", strings.ToUpper(r.Protocol))
	kvLine(2, "server", r.Server)
	renderTrace(r.Trace)
	fmt.Println("  " + paint(cDim, "data"))
	switch d := r.Data.(type) {
	case string:
		renderWhoisText(d, 2)
	case map[string]any:
		renderRDAP(d, 2)
	default:
		renderAny(d, 2)
	}
}

func renderTrace(hops []Hop) {
	if len(hops) == 0 {
		return
	}
	fmt.Println("  " + paint(cDim, "trace"))
	for _, h := range hops {
		mark, markColor := "✓", cGreen
		if h.Status != "OK" && !strings.Contains(h.Status, "HTTP 2") {
			mark, markColor = "✗", cRed
		}
		fmt.Printf("    %s %s %s  %s\n",
			paint(markColor, mark),
			paint(cPurple, fmt.Sprintf("%-5s", h.Protocol)),
			paint(cFg, h.Server),
			paint(cDim, truncate(strings.Join(strings.Fields(h.Status), " "), 90)))
	}
}

// truncate is rune-aware so multi-byte banner and status text stay intact.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max || max < 2 {
		return s
	}
	return string(r[:max-1]) + "…"
}

// ---------------------------------------------------------------------------
// WHOIS plain-text records
// ---------------------------------------------------------------------------

const (
	rowBlank = iota
	rowField
	rowNote
)

type whoisRow struct {
	kind int
	key  string
	val  string
	note string
}

func renderWhoisText(raw string, indent int) {
	pad := strings.Repeat("  ", indent)
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")

	rows := make([]whoisRow, 0, len(lines))
	width := 0
	for _, line := range lines {
		line = strings.TrimRight(line, "\r \t")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			rows = append(rows, whoisRow{kind: rowBlank})
		case strings.HasPrefix(trimmed, "%"), strings.HasPrefix(trimmed, "#"),
			strings.HasPrefix(trimmed, ">>>"), strings.HasPrefix(trimmed, "NOTICE"),
			strings.HasPrefix(trimmed, "TERMS"):
			rows = append(rows, whoisRow{kind: rowNote, note: trimmed})
		default:
			if i := strings.Index(line, ":"); i > 0 {
				key := strings.TrimSpace(line[:i])
				val := strings.TrimSpace(line[i+1:])
				if val != "" && isSimpleKey(key) {
					rows = append(rows, whoisRow{kind: rowField, key: key, val: val})
					if len(key) > width {
						width = len(key)
					}
					continue
				}
			}
			rows = append(rows, whoisRow{kind: rowNote, note: trimmed})
		}
	}

	// Collapse runs of blank lines so long records stay readable.
	blank := false
	for _, r := range rows {
		if r.kind == rowBlank {
			if blank {
				continue
			}
			blank = true
			fmt.Println()
			continue
		}
		blank = false
		switch r.kind {
		case rowField:
			fmt.Println(pad + paint(cCyan, fmt.Sprintf("%-*s", width, r.key)) +
				paint(cDim, " : ") + paint(cFg, r.val))
		default:
			fmt.Println(pad + paint(cDim, r.note))
		}
	}
}

func isSimpleKey(k string) bool {
	if k == "" || len(k) > 24 {
		return false
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ', r == '-', r == '_', r == '.', r == '/', r == '(', r == ')':
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// RDAP domain objects as a registrar-style text block
// ---------------------------------------------------------------------------

func renderRDAP(m map[string]any, indent int) {
	pad := strings.Repeat("  ", indent)
	matched := false
	line := func(key, value string) {
		if value == "" {
			return
		}
		matched = true
		fmt.Println(pad + paint(cCyan, fmt.Sprintf("%-12s", key)) + " " + paint(cFg, value))
	}

	if name := strings.ToLower(str(m["ldhName"])); name != "" {
		line("domain", name)
	}
	if h := str(m["handle"]); h != "" {
		line("handle", h)
	}
	if s := strings.Join(strList(m["status"]), ", "); s != "" {
		line("status", s)
	}

	registrar := ""
	abuse := []string{}
	walkEntities(m["entities"], func(e map[string]any) {
		roles := strList(e["roles"])
		switch {
		case hasRole(roles, "registrar"):
			if name := vcardName(e); name != "" && registrar == "" {
				registrar = name
			}
		case hasRole(roles, "abuse"):
			if name := vcardName(e); name != "" {
				abuse = append(abuse, name)
			}
			for _, email := range vcardValues(e, "email") {
				abuse = append(abuse, email)
			}
		}
	})
	line("registrar", registrar)
	line("abuse", strings.Join(dedupe(abuse), ", "))

	events := map[string]string{}
	for _, e := range mapList(m["events"]) {
		action := eventLabel(strings.ToLower(str(e["eventAction"])))
		date := str(e["eventDate"])
		if action != "" && date != "" {
			events[action] = date
		}
	}
	for _, key := range []string{"created", "updated", "expires", "transferred"} {
		line(key, events[key])
	}
	var extra []string
	for key := range events {
		switch key {
		case "created", "updated", "expires", "transferred":
		default:
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		line(key, events[key])
	}

	nameservers := []string{}
	for _, n := range mapList(m["nameservers"]) {
		if name := strings.ToLower(str(n["ldhName"])); name != "" {
			nameservers = append(nameservers, name)
		}
	}
	if len(nameservers) > 0 {
		line("nameservers", strings.Join(nameservers, ", "))
	}

	if dns, ok := m["secureDNS"].(map[string]any); ok {
		if signed, ok := dns["delegationSigned"].(bool); ok {
			if signed {
				line("dnssec", "signed")
			} else {
				line("dnssec", "unsigned")
			}
		}
	}

	// Unknown schema: fall back to a readable tree rather than dumping JSON.
	if !matched {
		renderMap(m, indent)
	}
}

func walkEntities(v any, fn func(map[string]any)) {
	for _, e := range mapList(v) {
		fn(e)
		walkEntities(e["entities"], fn)
	}
}

func vcardName(e map[string]any) string {
	if fn := vcardValues(e, "fn"); len(fn) > 0 {
		return fn[0]
	}
	if org := vcardValues(e, "org"); len(org) > 0 {
		return org[0]
	}
	return str(e["handle"])
}

func vcardValues(e map[string]any, key string) []string {
	arr, ok := e["vcardArray"].([]any)
	if !ok || len(arr) < 2 {
		return nil
	}
	entries, ok := arr[1].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range entries {
		row, ok := item.([]any)
		if !ok || len(row) < 4 || !strings.EqualFold(str(row[0]), key) {
			continue
		}
		if s := str(row[3]); s != "" {
			out = append(out, s)
			continue
		}
		out = append(out, strList(row[3])...)
	}
	return out
}

func eventLabel(action string) string {
	switch action {
	case "registration":
		return "created"
	case "expiration":
		return "expires"
	case "last changed":
		return "updated"
	case "transfer":
		return "transferred"
	case "last update of rdap database":
		return "rdap updated"
	case "":
		return ""
	}
	return action
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if strings.EqualFold(role, want) {
			return true
		}
	}
	return false
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// ---------------------------------------------------------------------------
// Generic readable renderer (no braces, no quoted JSON)
// ---------------------------------------------------------------------------

func renderAny(v any, indent int) {
	switch x := normalizeVal(v).(type) {
	case map[string]any:
		renderMap(x, indent)
	case []any:
		renderList(x, indent)
	default:
		if s, ok := scalarText(x); ok {
			fmt.Println(strings.Repeat("  ", indent) + paintScalar(x, s))
		}
	}
}

func renderMap(m map[string]any, indent int) {
	pad := strings.Repeat("  ", indent)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	width := 0
	for _, k := range keys {
		if l := len(humanKey(k)); l > width && l <= 22 {
			width = l
		}
	}
	if width < 6 {
		width = 6
	}

	for _, k := range keys {
		v := normalizeVal(m[k])
		label := paint(cCyan, fmt.Sprintf("%-*s", width, humanKey(k)))
		switch x := v.(type) {
		case map[string]any:
			fmt.Println(pad + label)
			renderMap(x, indent+1)
		case []any:
			switch {
			case len(x) == 0:
				fmt.Println(pad + label + "  " + paint(cDim, "—"))
			default:
				if s, ok := joinScalars(x); ok {
					fmt.Println(pad + label + "  " + s)
				} else {
					fmt.Println(pad + label)
					renderList(x, indent+1)
				}
			}
		default:
			if s, ok := scalarText(v); ok {
				if s == "" {
					s = "—"
				}
				fmt.Println(pad + label + "  " + paintScalar(v, s))
			} else {
				fmt.Println(pad + label + "  " + paint(cDim, fmt.Sprint(v)))
			}
		}
	}
}

func renderList(items []any, indent int) {
	pad := strings.Repeat("  ", indent)
	for _, item := range items {
		switch x := normalizeVal(item).(type) {
		case map[string]any:
			if line, ok := inlineMap(x); ok {
				fmt.Println(pad + paint(cDim, "• ") + line)
			} else {
				fmt.Println(pad + paint(cDim, "•"))
				renderMap(x, indent+1)
			}
		case []any:
			fmt.Println(pad + paint(cDim, "•"))
			renderList(x, indent+1)
		default:
			s, ok := scalarText(x)
			if !ok || s == "" {
				s = "—"
			}
			fmt.Println(pad + paint(cDim, "• ") + paintScalar(x, s))
		}
	}
}

// inlineMap renders arrays of flat objects as a single tidy line.
func inlineMap(m map[string]any) (string, bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := normalizeVal(m[k])
		switch v.(type) {
		case map[string]any, []any:
			return "", false
		}
		s, ok := scalarText(v)
		if !ok {
			return "", false
		}
		if s == "" {
			s = "—"
		}
		parts = append(parts, paint(cDim, humanKey(k)+" ")+paintScalar(v, s))
	}
	return strings.Join(parts, paint(cDim, "  ·  ")), true
}

func joinScalars(items []any) (string, bool) {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		v := normalizeVal(item)
		switch v.(type) {
		case map[string]any, []any:
			return "", false
		}
		s, ok := scalarText(v)
		if !ok {
			return "", false
		}
		parts = append(parts, paintScalar(v, s))
	}
	return strings.Join(parts, paint(cDim, ", ")), true
}

func humanKey(k string) string {
	return strings.ReplaceAll(k, "_", " ")
}

func normalizeVal(v any) any {
	switch v.(type) {
	case map[string]any, []any:
		return v
	}
	return toGeneric(v)
}

func toGeneric(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return string(b)
	}
	return out
}

func scalarText(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), true
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return x.String(), true
	}
	return "", false
}

func paintScalar(v any, s string) string {
	if s == "" || s == "—" {
		return paint(cDim, "—")
	}
	switch x := v.(type) {
	case bool:
		if x {
			return paint(cGreen, s)
		}
		return paint(cRed, s)
	case float64, json.Number:
		return paint(cYellow, s)
	case string:
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, "https://"), strings.HasPrefix(low, "http://"):
			return paint(cBlue, s)
		case strings.Contains(low, "error"), strings.Contains(low, "fail"),
			strings.Contains(low, "unavailable"), strings.Contains(low, "timeout"),
			strings.Contains(low, "refused"), strings.Contains(low, "invalid"):
			return paint(cRed, s)
		}
	}
	return paint(cFg, s)
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

func strList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s := str(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func mapList(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
