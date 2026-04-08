package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Hop represents a single hop in a traceroute.
type Hop struct {
	TTL     int
	IP      net.IP
	RTT     time.Duration
	Timeout bool
}

// traceroute sends probes with increasing TTLs and returns each responding hop.
// It requires CAP_NET_RAW (Linux) or root privileges.
func traceroute(dest net.IP, maxHops int, timeout time.Duration) ([]Hop, error) {
	isIPv6 := dest.To4() == nil
	if isIPv6 {
		return traceroute6(dest, maxHops, timeout)
	}
	return traceroute4(dest, maxHops, timeout)
}

func traceroute4(dest net.IP, maxHops int, timeout time.Duration) ([]Hop, error) {
	// Open raw ICMP listener for replies.
	lc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open ICMP listener (need root/CAP_NET_RAW): %w", err)
	}
	defer lc.Close()

	destAddr := &net.UDPAddr{IP: dest, Port: 33434}
	var hops []Hop

	for ttl := 1; ttl <= maxHops; ttl++ {
		// Dial UDP with custom TTL.
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dest, Port: 33434 + ttl})
		if err != nil {
			return hops, fmt.Errorf("dial UDP: %w", err)
		}
		if err := ipv4.NewConn(conn).SetTTL(ttl); err != nil {
			conn.Close()
			return hops, fmt.Errorf("set TTL: %w", err)
		}

		start := time.Now()
		_, _ = conn.Write([]byte("tlshop"))
		conn.Close()

		// Wait for ICMP Time Exceeded or Destination Unreachable.
		lc.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		n, peer, err := lc.ReadFrom(buf)
		rtt := time.Since(start)
		if err != nil {
			// Timeout — no response from this hop.
			hops = append(hops, Hop{TTL: ttl, Timeout: true})
			continue
		}

		msg, err := icmp.ParseMessage(1 /* ICMPv4 */, buf[:n])
		if err != nil {
			hops = append(hops, Hop{TTL: ttl, Timeout: true})
			continue
		}

		hopIP := net.ParseIP(peer.String())
		if udpAddr, ok := peer.(*net.UDPAddr); ok {
			hopIP = udpAddr.IP
		} else if ipAddr, ok := peer.(*net.IPAddr); ok {
			hopIP = ipAddr.IP
		}

		hop := Hop{TTL: ttl, IP: hopIP, RTT: rtt}
		hops = append(hops, hop)

		// Stop when we reach the destination (ICMP Port Unreachable = destination).
		if msg.Type == ipv4.ICMPTypeDestinationUnreachable || hopIP.Equal(dest) {
			break
		}
	}

	_ = destAddr
	return hops, nil
}

func traceroute6(dest net.IP, maxHops int, timeout time.Duration) ([]Hop, error) {
	lc, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open ICMPv6 listener (need root/CAP_NET_RAW): %w", err)
	}
	defer lc.Close()

	var hops []Hop
	for ttl := 1; ttl <= maxHops; ttl++ {
		conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: dest, Port: 33434 + ttl})
		if err != nil {
			return hops, fmt.Errorf("dial UDP: %w", err)
		}
		if err := ipv6.NewConn(conn).SetHopLimit(ttl); err != nil {
			conn.Close()
			return hops, fmt.Errorf("set hop limit: %w", err)
		}

		start := time.Now()
		_, _ = conn.Write([]byte("tlshop"))
		conn.Close()

		lc.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		n, peer, err := lc.ReadFrom(buf)
		rtt := time.Since(start)
		if err != nil {
			hops = append(hops, Hop{TTL: ttl, Timeout: true})
			continue
		}

		msg, err := icmp.ParseMessage(58 /* ICMPv6 */, buf[:n])
		if err != nil {
			hops = append(hops, Hop{TTL: ttl, Timeout: true})
			continue
		}

		hopIP := net.ParseIP(peer.String())
		if udpAddr, ok := peer.(*net.UDPAddr); ok {
			hopIP = udpAddr.IP
		} else if ipAddr, ok := peer.(*net.IPAddr); ok {
			hopIP = ipAddr.IP
		}

		hop := Hop{TTL: ttl, IP: hopIP, RTT: rtt}
		hops = append(hops, hop)

		if msg.Type == ipv6.ICMPTypeDestinationUnreachable || hopIP.Equal(dest) {
			break
		}
	}

	return hops, nil
}

// resolveHost resolves a hostname/IP string to a net.IP.
// If the input is already an IP, it is returned as-is.
func resolveHost(host string) (net.IP, []string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, []string{host}, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, nil, err
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no addresses found for %s", host)
	}
	ip := net.ParseIP(addrs[0])
	return ip, addrs, nil
}

// printHopHeader prints the traceroute header line for a hop.
func printHopHeader(h Hop) {
	if h.Timeout {
		fmt.Fprintf(os.Stdout, "  %2d  * * *  (no response)\n", h.TTL)
		return
	}
	names, err := net.LookupAddr(h.IP.String())
	hostname := ""
	if err == nil && len(names) > 0 {
		hostname = " (" + names[0] + ")"
	}
	fmt.Fprintf(os.Stdout, "  %2d  %-16s%s  RTT %v\n", h.TTL, h.IP, hostname, h.RTT.Round(time.Microsecond))
}
