package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const bootstrapURL = "https://data.iana.org/rdap/dns.json"
const ethiopiaRDAPBase = "https://rdap.ethiotelecom.et/rdap/"
const ethiopiaWHOISHost = "whois.ethiotelecom.et"

func isEthiopianDomain(domain string) bool {
	return strings.HasSuffix(domain, ".et")
}

func rdapBasesForDomain(domain string, bootstrap Bootstrap) []string {
	if isEthiopianDomain(domain) {
		return []string{ethiopiaRDAPBase}
	}
	return findBases(bootstrap, domain)
}

const maxBytes = 4 << 20
const maxHops = 12

type Bootstrap struct {
	Services [][][]string `json:"services"`
}
type Link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type"`
}
type RDAP struct {
	ObjectClass string `json:"objectClassName"`
	LDHName     string `json:"ldhName"`
	Links       []Link `json:"links"`
	Entities    []struct {
		Roles []string `json:"roles"`
		Links []Link   `json:"links"`
	} `json:"entities"`
}
type Hop struct {
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Status   string `json:"status"`
}
type Result struct {
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Trace    []Hop  `json:"trace"`
	Data     any    `json:"data"`
}
type Client struct {
	http    *http.Client
	timeout time.Duration
	verbose bool
}

func (c *Client) getJSON(ctx context.Context, uri string, out any) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")
	req.Header.Set("User-Agent", "gowhois/1.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return resp.StatusCode, resp.Request.URL.String(), err
	}
	if len(b) > maxBytes {
		return resp.StatusCode, resp.Request.URL.String(), errors.New("response too large")
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, resp.Request.URL.String(), fmt.Errorf("HTTP %d: %.160s", resp.StatusCode, string(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return resp.StatusCode, resp.Request.URL.String(), err
	}
	return resp.StatusCode, resp.Request.URL.String(), nil
}
func normalize(d string) (string, error) {
	d = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(d)), ".")
	if strings.ContainsAny(d, "/\\:@?# \t\n") || len(d) > 253 || len(d) < 3 {
		return "", errors.New("invalid domain")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("expected a domain, e.g. example.com")
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", errors.New("use ASCII/punycode domain labels")
			}
		}
	}
	return d, nil
}
func findBases(b Bootstrap, domain string) []string {
	best := -1
	var bases []string
	for _, svc := range b.Services {
		if len(svc) < 2 {
			continue
		}
		for _, suffix := range svc[0] {
			s := strings.ToLower(strings.TrimPrefix(suffix, "."))
			if domain == s || strings.HasSuffix(domain, "."+s) {
				if len(s) > best {
					best = len(s)
					bases = nil
				}
				if len(s) == best {
					bases = append(bases, svc[1]...)
				}
			}
		}
	}
	seen := map[string]bool{}
	var result []string
	for _, v := range bases {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	return result
}
func rdapURL(base, domain string) string {
	return strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(domain)
}
func safeRDAPLink(raw, domain string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return false
	}
	p := strings.ToLower(strings.TrimSuffix(u.EscapedPath(), "/"))
	return strings.HasSuffix(p, "/domain/"+strings.ToLower(url.PathEscape(domain)))
}
func referralLinks(r RDAP, domain string) []string {
	var items []Link
	items = append(items, r.Links...)
	for _, e := range r.Entities {
		registrar := false
		for _, role := range e.Roles {
			if strings.EqualFold(role, "registrar") {
				registrar = true
			}
		}
		if registrar {
			items = append(items, e.Links...)
		}
	}
	seen := map[string]bool{}
	var result []string
	for _, l := range items {
		if !strings.EqualFold(l.Rel, "related") {
			continue
		}
		if l.Type != "" && !strings.Contains(strings.ToLower(l.Type), "rdap+json") {
			continue
		}
		if !safeRDAPLink(l.Href, domain) || seen[l.Href] {
			continue
		}
		result = append(result, l.Href)
		seen[l.Href] = true
	}
	return result
}
func (c *Client) lookupRDAP(ctx context.Context, domain string, trace *[]Hop) (Result, error) {
	var boot Bootstrap
	if !isEthiopianDomain(domain) {
		_, _, err := c.getJSON(ctx, bootstrapURL, &boot)
		if err != nil {
			return Result{}, fmt.Errorf("bootstrap: %w", err)
		}
	}
	bases := rdapBasesForDomain(domain, boot)
	if len(bases) == 0 {
		return Result{}, errors.New("no RDAP bootstrap service for this TLD")
	}
	seen := map[string]bool{}
	var latest Result
	var failures []string
	var walk func(string, int)
	walk = func(uri string, depth int) {
		if depth >= maxHops || seen[uri] {
			return
		}
		seen[uri] = true
		var data map[string]any
		status, final, err := c.getJSON(ctx, uri, &data)
		h := Hop{Protocol: "rdap", Server: uri, Status: fmt.Sprintf("HTTP %d", status)}
		if err != nil {
			h.Status = err.Error()
			*trace = append(*trace, h)
			failures = append(failures, err.Error())
			return
		}
		if final != uri {
			h.Status += " -> " + final
		}
		*trace = append(*trace, h)
		// A valid RDAP domain object is required; generic JSON error documents don't count.
		var parsed RDAP
		raw, _ := json.Marshal(data)
		_ = json.Unmarshal(raw, &parsed)
		if parsed.ObjectClass != "domain" {
			failures = append(failures, "not an RDAP domain object: "+uri)
			return
		}
		latest = Result{Domain: domain, Protocol: "rdap", Server: final, Data: data}
		for _, next := range referralLinks(parsed, domain) {
			walk(next, depth+1)
		}
	}
	for _, base := range bases {
		walk(rdapURL(base, domain), 0)
		if latest.Data != nil {
			break
		}
	}
	if latest.Data == nil {
		return Result{}, fmt.Errorf("RDAP unavailable: %s", strings.Join(failures, "; "))
	}
	latest.Trace = append([]Hop(nil), (*trace)...)
	return latest, nil
}

var referralPattern = regexp.MustCompile(`(?im)^\s*(?:refer|whois server|registrar whois server|referralserver)\s*:\s*(?:whois://)?([^\s]+)`)

func sanitizeHost(raw string) string {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "."))
	raw = strings.TrimPrefix(raw, "whois://")
	raw = strings.TrimSuffix(raw, "/")
	if strings.ContainsAny(raw, "/@?#\\") {
		return ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		if port != "43" {
			return ""
		}
		raw = host
	}
	if len(raw) > 253 || raw == "" {
		return ""
	}
	for _, r := range raw {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return ""
		}
	}
	return strings.ToLower(raw)
}
func referral(body string) string {
	m := referralPattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return sanitizeHost(m[1])
}
func (c *Client) whois(ctx context.Context, host, domain string) (string, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err = io.WriteString(conn, domain+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, maxBytes+1))
	if len(b) > maxBytes {
		return "", errors.New("WHOIS response too large")
	}
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return "", errors.New("empty WHOIS response")
	}
	return string(b), nil
}
func (c *Client) lookupWHOIS(ctx context.Context, domain string, trace *[]Hop) (Result, error) {
	host := "whois.iana.org"
	if isEthiopianDomain(domain) {
		host = ethiopiaWHOISHost
	}
	seen := map[string]bool{}
	var latest Result
	var failures []string
	for i := 0; i < maxHops && host != ""; i++ {
		if seen[host] {
			break
		}
		seen[host] = true
		body, err := c.whois(ctx, host, domain)
		if err != nil {
			*trace = append(*trace, Hop{Protocol: "whois", Server: host, Status: err.Error()})
			failures = append(failures, host+": "+err.Error())
			break
		}
		*trace = append(*trace, Hop{Protocol: "whois", Server: host, Status: "OK"})
		latest = Result{Domain: domain, Protocol: "whois", Server: host, Data: body}
		next := referral(body)
		if next == host {
			break
		}
		host = next
	}
	if latest.Data == nil {
		return Result{}, fmt.Errorf("WHOIS failed: %s", strings.Join(failures, "; "))
	}
	latest.Trace = append([]Hop(nil), (*trace)...)
	return latest, nil
}
