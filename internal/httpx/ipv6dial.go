package httpx

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Local DNS hijacks opencode.ai to 198.18.x.x, and the hijacked IPv4 exit is
// rejected by the upstream free tier with 403 FreeTierError. The domain has
// real AAAA records (Cloudflare) and the same request over native IPv6 is
// accepted, so direct connections to *.opencode.ai resolve AAAA via DoH
// (IP-literal endpoints, no system DNS involved) and dial IPv6 first.
//
// The behavior is gated by config.ipv6_first (default on) because some routes
// only serve over IPv4, so the operator can turn it off from the WebUI.
// dohEndpoints are JSON DoH resolvers addressed by IP literal, so resolving
// them never depends on the system resolver that is being bypassed. The paths
// differ: Cloudflare serves the JSON API on /dns-query, Google on /resolve
// (/dns-query there expects the RFC 8484 wire format and answers 400).
var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/resolve",
}

var dohClient = &http.Client{Timeout: 5 * time.Second}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"Type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type v6CacheEntry struct {
	ips []string
	exp time.Time
}

var (
	v6CacheMu sync.Mutex
	v6Cache   = map[string]v6CacheEntry{}
)

func opencodeHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "opencode.ai" || strings.HasSuffix(host, ".opencode.ai")
}

// resolveOpencodeIPv6 returns cached-or-fresh AAAA records for *.opencode.ai
// via DoH. Empty means "no IPv6 info, use the system path".
func resolveOpencodeIPv6(ctx context.Context, host string) []string {
	v6CacheMu.Lock()
	if e, ok := v6Cache[host]; ok && time.Now().Before(e.exp) {
		ips := e.ips
		v6CacheMu.Unlock()
		return ips
	}
	v6CacheMu.Unlock()

	for _, endpoint := range dohEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?name="+host+"&type=AAAA", nil)
		if err != nil {
			continue
		}
		req.Header.Set("accept", "application/dns-json")
		resp, err := dohClient.Do(req)
		if err != nil {
			continue
		}
		var decoded dohResponse
		func() {
			defer resp.Body.Close()
			_ = json.NewDecoder(resp.Body).Decode(&decoded)
		}()
		if decoded.Status != 0 {
			continue
		}
		var ips []string
		for _, a := range decoded.Answer {
			if a.Type != 28 {
				continue
			}
			if ip := net.ParseIP(a.Data); ip != nil {
				ips = append(ips, a.Data)
			}
		}
		if len(ips) > 0 {
			v6CacheMu.Lock()
			v6Cache[host] = v6CacheEntry{ips: ips, exp: time.Now().Add(4 * time.Minute)}
			v6CacheMu.Unlock()
			return ips
		}
	}
	return nil
}

// DialIPv6First wraps base so *.opencode.ai dials its real IPv6 first and
// only falls back to the system path when IPv6 is unreachable. Non-OpenCode
// hosts (including proxy addresses) use base unchanged. The SNI/host header
// still carries the original domain, only the TCP destination changes.
//
// When enabled is false the base dialer is returned untouched, which restores
// plain system resolution. That is the escape hatch for exits where IPv6 is
// unusable or where a specific upstream route only works over IPv4.
func DialIPv6First(base *net.Dialer, enabled bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	if !enabled {
		return base.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return base.DialContext(ctx, network, address)
		}
		if net.ParseIP(host) != nil || !opencodeHost(host) {
			return base.DialContext(ctx, network, address)
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips := resolveOpencodeIPv6(lookupCtx, host)
		cancel()
		for _, ip := range ips {
			dialCtx, stop := context.WithTimeout(ctx, base.Timeout)
			conn, err := base.DialContext(dialCtx, network, net.JoinHostPort(ip, port))
			stop()
			if err == nil {
				return conn, nil
			}
		}
		return base.DialContext(ctx, network, address)
	}
}

// DirectTransport returns an http.Transport clone routing *.opencode.ai over
// IPv6 first when ipv6First is set. It exists for one-off clients that do not
// go through the gateway transport pool.
func DirectTransport(timeout time.Duration, ipv6First bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = DialIPv6First(&net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}, ipv6First)
	transport.Proxy = nil
	return transport
}
