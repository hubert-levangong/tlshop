# tlshop

`tlshop` is a command-line tool that combines **traceroute** with **TLS inspection**.  
For each network hop on the path to a target host it attempts a TLS handshake on the
specified port and prints full negotiation details.

## What it shows

| Field | Source |
|-------|--------|
| TLS version | `tls.ConnectionState.Version` |
| Cipher suite name + hex ID | `tls.CipherSuiteName` |
| ALPN protocol | `tls.ConnectionState.NegotiatedProtocol` |
| Session resumption | `tls.ConnectionState.DidResume` |
| Leaf / intermediate / root certificates | `tls.ConnectionState.PeerCertificates` |
| Certificate subject, issuer, SANs | `x509.Certificate` |
| Validity window | `x509.Certificate.NotBefore/NotAfter` |
| Public key type and size (RSA, ECDSA, Ed25519) | `x509.Certificate.PublicKey` |
| Signature algorithm | `x509.Certificate.SignatureAlgorithm` |

> **Key-exchange group** (X25519, P-256 …) — Go's `crypto/tls` does not expose the
> negotiated group in `ConnectionState`.  The cipher suite name implies ephemeral
> key exchange (ECDHE/DHE); for exact group visibility you would need to inspect the
> raw `key_share` extension in the ServerHello.

## Requirements

* Go 1.21+
* **Root / `CAP_NET_RAW`** for the traceroute component (raw ICMP sockets).
  TLS probing itself does not require elevated privileges.

## Build

```sh
git clone https://github.com/hubert-levangong/tlshop
cd tlshop
go build -o tlshop .
```

## Usage

```
sudo ./tlshop [flags] <host | URL>

Flags:
  -hops int      Maximum traceroute hops (default 30)
  -port int      TCP port to probe for TLS (default 443)
  -timeout dur   Per-hop timeout (default 3s)
  -sni  string   Override TLS SNI (default: target hostname)
```

### Examples

```sh
# Trace to example.com and probe TLS on each hop
sudo ./tlshop example.com

# Full URL — port and SNI are inferred automatically
sudo ./tlshop https://api.github.com

# Custom port and SNI override
sudo ./tlshop -port 8443 -sni internal.example.com 10.0.1.50

# Longer timeout for slow/distant targets
sudo ./tlshop -timeout 5s -hops 40 cloudflare.com
```

### Sample output

```
tlshop — TLS-aware traceroute
Target  : example.com
DNS     : 93.184.216.34
Dest IP : 93.184.216.34
TLS Port: 443   SNI: example.com
────────────────────────────────────────────────────────────
   1  192.168.1.1                   RTT 1.2ms
        TLS: unavailable — dial tcp 192.168.1.1:443: connect: connection refused
   2  10.0.0.1                      RTT 5.4ms
        TLS: unavailable — i/o timeout
  ...
  12  93.184.216.34                 RTT 11ms
        TLS Version : TLS 1.3
        Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
        ALPN        : h2
        Key Exchange: see cipher suite (ECDHE/DHE implied by suite name)
        Cert[0] (leaf):
          Subject  : CN=www.example.org,O=Internet Corporation for...
          Issuer   : CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,...
          SANs     : www.example.org, example.net, example.com, ...
          Validity : 2024-01-15 → 2025-02-15
          PublicKey: ECDSA-256
          SigAlg   : ECDSAWithSHA256
        Cert[1] (intermediate):
          ...
```

## Architecture

```
main.go         CLI entry point, flag parsing, output loop
traceroute.go   Raw ICMP traceroute (IPv4 + IPv6)
tlsinfo.go      TLS dial, ConnectionState extraction, certificate summary
```

## License

MIT
