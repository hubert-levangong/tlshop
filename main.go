// tlshop — traceroute each network hop and probe TLS on port 443 (or a custom port).
//
// Usage:
//
//	sudo tlshop [flags] <host>
//
// Flags:
//
//	-hops int      Maximum traceroute hops (default 30)
//	-port int      TCP port to probe for TLS (default 443)
//	-timeout dur   Per-hop timeout (default 3s)
//	-sni string    Override SNI for TLS (default: original hostname)
//	-skip-verify   Disable TLS certificate verification
//
// Requires CAP_NET_RAW or root privileges for ICMP raw sockets used in
// traceroute. TLS probing does not need elevated privileges.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	maxHops := flag.Int("hops", 30, "Maximum number of traceroute hops")
	port := flag.Int("port", 443, "TCP port to probe for TLS on each hop")
	timeout := flag.Duration("timeout", 3*time.Second, "Per-hop timeout")
	sniOverride := flag.String("sni", "", "Override TLS SNI (default: target hostname)")
	flag.Parse()

	var raw string
	if flag.NArg() >= 1 {
		raw = flag.Arg(0)
	} else {
		fmt.Print("Enter target URL or IP address: ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintf(os.Stderr, "Usage: %s [flags] <host|URL>\n", os.Args[0])
			flag.PrintDefaults()
			os.Exit(1)
		}
		raw = strings.TrimSpace(scanner.Text())
		if raw == "" {
			fmt.Fprintf(os.Stderr, "Error: no target specified\n")
			os.Exit(1)
		}
	}
	hostname, destPort := parseTarget(raw)
	if destPort != 0 {
		*port = destPort
	}

	sni := hostname
	if *sniOverride != "" {
		sni = *sniOverride
	}

	destIP, allAddrs, err := resolveHost(hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %q: %v\n", hostname, err)
		os.Exit(1)
	}

	fmt.Printf("tlshop — TLS-aware traceroute\n")
	fmt.Printf("Target  : %s\n", hostname)
	if len(allAddrs) > 1 {
		fmt.Printf("DNS     : %s\n", strings.Join(allAddrs, ", "))
	}
	fmt.Printf("Dest IP : %s\n", destIP)
	fmt.Printf("TLS Port: %d   SNI: %s\n", *port, sni)
	fmt.Println(strings.Repeat("─", 60))

	hops, err := traceroute(destIP, *maxHops, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nTraceroute error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(Hint: run with sudo or grant CAP_NET_RAW)")
		os.Exit(1)
	}

	for _, hop := range hops {
		printHopHeader(hop)
		if hop.Timeout || hop.IP == nil {
			continue
		}
		addr := net.JoinHostPort(hop.IP.String(), strconv.Itoa(*port))
		// Use the original hostname as SNI only for the final destination.
		hopSNI := ""
		if hop.IP.Equal(destIP) {
			hopSNI = sni
		}
		result, tlsErr := probeTLS(addr, hopSNI, *timeout)
		if result == nil {
			fmt.Printf("        TLS: unavailable — %v\n", tlsErr)
			continue
		}
		if tlsErr != nil {
			// We got metadata despite a cert error.
			printTLSResult(result, tlsErr)
		} else {
			printTLSResult(result, nil)
		}
	}
}

// parseTarget extracts the hostname and optional port from a raw target string.
// Accepts plain hostnames, IP addresses, and full URLs.
func parseTarget(raw string) (host string, port int) {
	// If it looks like a URL, parse it properly.
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			h, p, err2 := net.SplitHostPort(u.Host)
			if err2 == nil {
				n, _ := strconv.Atoi(p)
				return h, n
			}
			return u.Hostname(), schemePort(u.Scheme)
		}
	}
	// host:port
	if h, p, err := net.SplitHostPort(raw); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return raw, 0
}

func schemePort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "https":
		return 443
	case "http":
		return 80
	case "ftps":
		return 990
	case "smtps":
		return 465
	default:
		return 0
	}
}
