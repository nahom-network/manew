package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 9 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
	if len(via) >= 8 {
		return errors.New("too many redirects")
	}
	if r.URL.Scheme != "https" && r.URL.Scheme != "http" {
		return errors.New("unsupported redirect")
	}
	return nil
}}

func ask(r *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}
func main() {
	enterTheme()
	defer exitTheme()
	installCleanup()

	r := bufio.NewReader(os.Stdin)
	renderBanner()
	for {
		renderMenu()
		ch := ask(r, "\n  "+paint(cPurple+cBold, "› "))
		if ch == "0" || strings.EqualFold(ch, "q") {
			fmt.Println("\n  " + paint(cDim, "Goodbye."))
			return
		}
		if len(ch) != 1 || ch[0] < '1' || ch[0] > '9' {
			fmt.Println("  " + paint(cRed, "✗ unknown option"))
			continue
		}
		target := ask(r, "  "+paint(cDim, "domain / host / ip")+paint(cDim, " › "))
		if target == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		var data any
		var err error
		switch ch {
		case "1":
			data, err = whoisLookup(ctx, target)
		case "2":
			data, err = dnsLookup(ctx, target)
		case "3":
			data, err = ipLookup(ctx, target)
		case "4":
			data, err = sslLookup(ctx, target)
		case "5":
			data, err = httpLookup(ctx, target)
		case "6":
			data, err = portLookup(ctx, target, r)
		case "7":
			data, err = subdomainLookup(ctx, target)
		case "8":
			data, err = healthLookup(ctx, target)
		case "9":
			data, err = threatLookup(ctx, target)
		}
		cancel()
		if err != nil {
			fmt.Println("  " + paint(cRed, "✗ "+err.Error()))
		} else {
			output(moduleLabels[ch], data)
		}
	}
}

var moduleLabels = map[string]string{
	"1": "WHOIS / RDAP", "2": "DNS", "3": "IP", "4": "SSL / TLS", "5": "HTTP",
	"6": "PORTS", "7": "SUBDOMAINS", "8": "HEALTH", "9": "THREAT",
}

func installCleanup() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		exitTheme()
		fmt.Println()
		os.Exit(130)
	}()
}
func hostOf(input string) (string, error) {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "://") {
		u, e := url.Parse(input)
		if e != nil {
			return "", e
		}
		input = u.Hostname()
	}
	input = strings.Trim(input, "[]")
	if ip := net.ParseIP(input); ip != nil {
		return ip.String(), nil
	}
	return normalize(input)
}
func whoisLookup(ctx context.Context, input string) (any, error) {
	d, e := normalize(input)
	if e != nil {
		return nil, e
	}
	c := &Client{timeout: 8 * time.Second}
	c.http = &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= maxHops || r.URL.Scheme != "https" {
			return errors.New("unsafe or excessive RDAP redirect")
		}
		return nil
	}}
	var trace []Hop
	result, rdapErr := c.lookupRDAP(ctx, d, &trace)
	if result.Data == nil {
		result, e = c.lookupWHOIS(ctx, d, &trace)
		if e != nil {
			return map[string]any{"rdap_error": fmt.Sprint(rdapErr), "whois_error": e.Error(), "trace": trace}, nil
		}
	}
	result.Trace = trace
	return result, nil
}
func dnsLookup(ctx context.Context, input string) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	rs := net.DefaultResolver
	out := map[string]any{"host": h}
	if v, e := rs.LookupIPAddr(ctx, h); e == nil {
		out["addresses"] = v
	} else {
		out["addresses_error"] = e.Error()
	}
	for _, q := range []struct {
		name string
		fn   func() (any, error)
	}{
		{"MX", func() (any, error) { return rs.LookupMX(ctx, h) }}, {"NS", func() (any, error) { return rs.LookupNS(ctx, h) }}, {"TXT", func() (any, error) { return rs.LookupTXT(ctx, h) }}, {"CNAME", func() (any, error) { return rs.LookupCNAME(ctx, h) }},
	} {
		if v, e := q.fn(); e == nil {
			out[q.name] = v
		} else {
			out[q.name+"_error"] = e.Error()
		}
	}
	return out, nil
}
func ipLookup(ctx context.Context, input string) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, h)
	if e != nil {
		return nil, e
	}
	out := map[string]any{"target": h, "ip_addresses": ips}
	for _, ip := range ips {
		names, _ := net.DefaultResolver.LookupAddr(ctx, ip.IP.String())
		out["ptr_"+ip.IP.String()] = names
	}
	return out, nil
}
func sslLookup(ctx context.Context, input string) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	c, e := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(h, "443"), &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12})
	if e != nil {
		return nil, e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	state := c.ConnectionState()
	res := map[string]any{"host": h, "tls_version": tls.VersionName(state.Version), "cipher_suite": tls.CipherSuiteName(state.CipherSuite), "verified_chains": len(state.VerifiedChains)}
	certs := []any{}
	for _, x := range state.PeerCertificates {
		certs = append(certs, map[string]any{"subject": x.Subject.String(), "issuer": x.Issuer.String(), "dns_names": x.DNSNames, "valid_from": x.NotBefore, "valid_until": x.NotAfter, "days_remaining": int(time.Until(x.NotAfter).Hours() / 24)})
	}
	res["certificates"] = certs
	return res, nil
}
func webURL(input string) (string, error) {
	input = strings.TrimSpace(input)
	if !strings.Contains(input, "://") {
		h, e := hostOf(input)
		if e != nil {
			return "", e
		}
		return "https://" + h, nil
	}
	u, e := url.Parse(input)
	if e != nil {
		return "", e
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("only http and https supported")
	}
	if _, e = hostOf(u.Hostname()); e != nil {
		return "", e
	}
	return input, nil
}
func httpLookup(ctx context.Context, input string) (any, error) {
	address, e := webURL(input)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "HEAD", address, nil)
	if e != nil {
		return nil, e
	}
	start := time.Now()
	res, e := httpClient.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	headers := map[string]string{}
	for _, k := range []string{"Server", "Content-Type", "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Location"} {
		if x := res.Header.Get(k); x != "" {
			headers[k] = x
		}
	}
	return map[string]any{"requested": address, "final_url": res.Request.URL.String(), "status": res.Status, "elapsed_ms": time.Since(start).Milliseconds(), "headers": headers}, nil
}
func portLookup(ctx context.Context, input string, r *bufio.Reader) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	fmt.Println("  " + paint(cYellow, "! Only scan hosts you own or have permission to test."))
	if strings.ToLower(ask(r, "  "+paint(cDim, "authorized? [yes/no]")+paint(cDim, " › "))) != "yes" {
		return nil, errors.New("port check cancelled")
	}
	raw := ask(r, "  "+paint(cDim, "ports (comma-separated, Enter for default)")+paint(cDim, " › "))
	if raw == "" {
		raw = "21,22,25,53,80,110,143,443,3306,5432,6379,8080,8443"
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		return nil, errors.New("maximum 64 ports per check")
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, part := range parts {
		p, e := strconv.Atoi(strings.TrimSpace(part))
		if e != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	type record struct {
		Port  int    `json:"port"`
		State string `json:"state"`
	}
	items := make([]record, len(ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for i, p := range ports {
		wg.Add(1)
		go func(i, p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			d := net.Dialer{Timeout: 1200 * time.Millisecond}
			c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(h, strconv.Itoa(p)))
			state := "closed_or_filtered"
			if e == nil {
				state = "open"
				_ = c.Close()
			}
			items[i] = record{p, state}
		}(i, p)
	}
	wg.Wait()
	sort.Slice(items, func(i, j int) bool { return items[i].Port < items[j].Port })
	return map[string]any{"host": h, "tcp_ports": items, "note": "A timeout cannot distinguish filtered from closed"}, nil
}
func subdomainLookup(ctx context.Context, input string) (any, error) {
	d, e := normalize(input)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "https://crt.sh/?q=%25."+url.QueryEscape(d)+"&output=json", nil)
	if e != nil {
		return nil, e
	}
	res, e := httpClient.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("certificate transparency service: HTTP %d", res.StatusCode)
	}
	var entries []struct {
		Name string `json:"name_value"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&entries); e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	names := []string{}
	for _, row := range entries {
		for _, name := range strings.Split(row.Name, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name != d && strings.HasSuffix(name, "."+d) && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	if len(names) > 250 {
		names = names[:250]
	}
	return map[string]any{"domain": d, "source": "crt.sh public certificate transparency logs", "subdomains": names, "count_returned": len(names), "note": "Passive certificate log discovery; not an exhaustive list or proof of active hosts"}, nil
}
func healthLookup(ctx context.Context, input string) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	result := map[string]any{"host": h}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, h)
	result["dns_ok"] = e == nil
	if e == nil {
		result["ip_count"] = len(ips)
	} else {
		result["dns_error"] = e.Error()
	}
	if v, e := sslLookup(ctx, h); e == nil {
		result["tls_ok"] = true
		result["tls"] = v
	} else {
		result["tls_ok"] = false
		result["tls_error"] = e.Error()
	}
	if v, e := httpLookup(ctx, h); e == nil {
		result["https_reachable"] = true
		result["http"] = v
	} else {
		result["https_reachable"] = false
		result["http_error"] = e.Error()
	}
	return result, nil
}
func threatLookup(ctx context.Context, input string) (any, error) {
	h, e := hostOf(input)
	if e != nil {
		return nil, e
	}
	out := map[string]any{"target": h, "disclaimer": "Informational DNSBL checks only; a missing listing does not mean a host is safe. DNSBLs primarily assess mail-sending IPs."}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, h)
	if e != nil {
		return nil, e
	}
	checks := []any{}
	for _, x := range ips {
		ip4 := x.IP.To4()
		if ip4 == nil {
			continue
		}
		rev := fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
		for _, zone := range []string{"zen.spamhaus.org", "bl.spamcop.net"} {
			q := rev + "." + zone
			addresses, e := net.DefaultResolver.LookupHost(ctx, q)
			status := "not_listed_or_unavailable"
			if e == nil {
				status = "response_received_check_provider_policy"
			}
			checks = append(checks, map[string]any{"ip": x.IP.String(), "provider": zone, "status": status, "answer": addresses})
		}
	}
	out["dnsbl_checks"] = checks
	return out, nil
}
