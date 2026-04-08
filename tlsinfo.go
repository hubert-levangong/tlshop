package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSResult holds all TLS handshake and certificate details for one probe.
type TLSResult struct {
	Addr     string
	SNI      string
	Version  string
	Cipher   string
	ALPN     string
	Resumed  bool
	Certs    []CertInfo
	RawState tls.ConnectionState
}

// CertInfo summarises one X.509 certificate in the chain.
type CertInfo struct {
	Subject   string
	Issuer    string
	SANs      []string
	NotBefore time.Time
	NotAfter  time.Time
	KeyType   string
	KeyBits   int
	SigAlg    string
	IsCA      bool
}

// probeTLS dials addr, performs a TLS handshake using sni as the server name,
// and returns rich details about the negotiated session and certificate chain.
func probeTLS(addr, sni string, timeout time.Duration) (*TLSResult, error) {
	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false, // verify by default; caller may override
		// Advertise all modern curve preferences so the server can pick.
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		// Request ALPN for HTTP/2 and HTTP/1.1.
		NextProtos: []string{"h2", "http/1.1"},
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		// Retry with certificate verification disabled so we still get TLS metadata
		// even for self-signed / expired certs.
		cfg2 := cfg.Clone()
		cfg2.InsecureSkipVerify = true
		conn2, err2 := tls.DialWithDialer(dialer, "tcp", addr, cfg2)
		if err2 != nil {
			return nil, err2
		}
		defer conn2.Close()
		result := buildResult(addr, sni, conn2.ConnectionState())
		result.RawState = conn2.ConnectionState()
		return result, fmt.Errorf("cert verification failed (%v); TLS metadata captured anyway", err)
	}
	defer conn.Close()
	result := buildResult(addr, sni, conn.ConnectionState())
	result.RawState = conn.ConnectionState()
	return result, nil
}

func buildResult(addr, sni string, cs tls.ConnectionState) *TLSResult {
	r := &TLSResult{
		Addr:    addr,
		SNI:     sni,
		Version: tlsVersionName(cs.Version),
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:    cs.NegotiatedProtocol,
		Resumed: cs.DidResume,
	}
	for _, cert := range cs.PeerCertificates {
		r.Certs = append(r.Certs, summariseCert(cert))
	}
	return r
}

func summariseCert(c *x509.Certificate) CertInfo {
	ci := CertInfo{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		SigAlg:    c.SignatureAlgorithm.String(),
		IsCA:      c.IsCA,
	}
	// SANs
	ci.SANs = append(ci.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		ci.SANs = append(ci.SANs, ip.String())
	}
	for _, uri := range c.URIs {
		ci.SANs = append(ci.SANs, uri.String())
	}
	// Public key
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyType = "RSA"
		ci.KeyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		ci.KeyType = "ECDSA"
		switch k.Curve {
		case elliptic.P256():
			ci.KeyBits = 256
		case elliptic.P384():
			ci.KeyBits = 384
		case elliptic.P521():
			ci.KeyBits = 521
		default:
			ci.KeyBits = k.Params().BitSize
		}
	case ed25519.PublicKey:
		ci.KeyType = "Ed25519"
		ci.KeyBits = 256
	default:
		ci.KeyType = fmt.Sprintf("%T", c.PublicKey)
	}
	return ci
}

// printTLSResult renders a TLSResult to stdout.
func printTLSResult(r *TLSResult, certVerifyErr error) {
	indent := "        "
	fmt.Printf("%sTLS Version : %s\n", indent, r.Version)
	fmt.Printf("%sCipher Suite: %s (0x%04x)\n", indent, r.Cipher, r.RawState.CipherSuite)
	if r.ALPN != "" {
		fmt.Printf("%sALPN        : %s\n", indent, r.ALPN)
	}
	if r.Resumed {
		fmt.Printf("%sSession     : resumed\n", indent)
	}
	if certVerifyErr != nil {
		fmt.Printf("%sCert verify : FAILED — %v\n", indent, certVerifyErr)
	}
	// Negotiated key-exchange group (accessible via raw ServerHello key_share
	// extension; Go's crypto/tls doesn't expose it directly).
	fmt.Printf("%sKey Exchange: see cipher suite (ECDHE/DHE implied by suite name)\n", indent)

	for i, cert := range r.Certs {
		role := "leaf"
		if i == len(r.Certs)-1 && cert.IsCA {
			role = "root CA"
		} else if i > 0 {
			role = "intermediate"
		}
		fmt.Printf("%sCert[%d] (%s):\n", indent, i, role)
		fmt.Printf("%s  Subject  : %s\n", indent, cert.Subject)
		fmt.Printf("%s  Issuer   : %s\n", indent, cert.Issuer)
		if len(cert.SANs) > 0 {
			fmt.Printf("%s  SANs     : %s\n", indent, strings.Join(cert.SANs, ", "))
		}
		fmt.Printf("%s  Validity : %s → %s\n", indent,
			cert.NotBefore.UTC().Format("2006-01-02"),
			cert.NotAfter.UTC().Format("2006-01-02"))
		fmt.Printf("%s  PublicKey: %s-%d\n", indent, cert.KeyType, cert.KeyBits)
		fmt.Printf("%s  SigAlg   : %s\n", indent, cert.SigAlg)
	}
}

// tlsVersionName maps a TLS version uint16 to a human-readable name.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// cipherSuiteHex returns the hex representation of a cipher suite ID.
func cipherSuiteHex(id uint16) string {
	b := [2]byte{byte(id >> 8), byte(id)}
	return "0x" + hex.EncodeToString(b[:])
}
