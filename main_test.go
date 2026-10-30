package main

import "testing"

func TestBootstrap(t *testing.T) {
	b := Bootstrap{Services: [][][]string{{{"com"}, {"https://first.example/"}}, {{"uk", "co.uk"}, {"https://second.example/"}}}}
	v := findBases(b, "foo.co.uk")
	if len(v) != 1 || v[0] != "https://second.example/" {
		t.Fatalf("unexpected bases: %v", v)
	}
}
func TestReferral(t *testing.T) {
	s := "% IANA\nrefer: whois.example.test\n"
	if referral(s) != "whois.example.test" {
		t.Fatal("missing referral")
	}
	if referral("ReferralServer: whois://whois.example.test:43") != "whois.example.test" {
		t.Fatal("invalid port parsing")
	}
}
func TestRDAPRelated(t *testing.T) {
	r := RDAP{Links: []Link{{Rel: "related", Href: "https://registrar.example/rdap/domain/example.com", Type: "application/rdap+json"}, {Rel: "related", Href: "https://other.example/privacy", Type: "text/html"}}}
	x := referralLinks(r, "example.com")
	if len(x) != 1 {
		t.Fatalf("unexpected links %v", x)
	}
}

func TestEthiopianEndpoints(t *testing.T) {
	for _, domain := range []string{"example.et", "example.com.et", "sub.example.gov.et"} {
		if !isEthiopianDomain(domain) {
			t.Fatalf("not detected: %s", domain)
		}
		bases := rdapBasesForDomain(domain, Bootstrap{})
		want := "https://rdap.ethiotelecom.et/rdap/domain/" + domain
		if len(bases) != 1 || rdapURL(bases[0], domain) != want {
			t.Fatalf("unexpected RDAP endpoint for %s: %v", domain, bases)
		}
	}
	if isEthiopianDomain("notet.com") || isEthiopianDomain("example.com") {
		t.Fatal("incorrectly classified non-Ethiopian domain")
	}
}
