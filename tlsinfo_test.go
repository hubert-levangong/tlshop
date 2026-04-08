package main

import (
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeTLS(t *testing.T) {
	// Spin up a local TLS test server.
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	_ = portStr

	addr := srv.Listener.Addr().String()
	// httptest uses a self-signed cert, so InsecureSkipVerify will kick in.
	result, err := probeTLS(addr, host, 5*time.Second)
	if result == nil {
		t.Fatalf("expected TLS result even with cert error, got nil (err: %v)", err)
	}
	if result.Version == "" {
		t.Error("TLS version should not be empty")
	}
	if result.Cipher == "" {
		t.Error("cipher suite should not be empty")
	}
	if len(result.Certs) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0301, "TLS 1.0"},
	}
	for _, c := range cases {
		if got := tlsVersionName(c.v); got != c.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantPort int
	}{
		{"example.com", "example.com", 0},
		{"example.com:8443", "example.com", 8443},
		{"https://example.com", "example.com", 443},
		{"https://example.com/path", "example.com", 443},
		{"http://example.com:8080/", "example.com", 8080},
	}
	for _, c := range cases {
		h, p := parseTarget(c.raw)
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("parseTarget(%q) = (%q, %d), want (%q, %d)", c.raw, h, p, c.wantHost, c.wantPort)
		}
	}
}
