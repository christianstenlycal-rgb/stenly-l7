package main
import (
	"bufio"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)
type ProxyEntry struct {
	Addr         string
	LastUsed     time.Time
	FailCount    int
	SuccessCount int
	AvgLatency   time.Duration
	Dead         bool
}
type dnsCacheEntry struct {
	addr       string
	resolvedAt time.Time
}
var (
	proxyList      []ProxyEntry
	proxyMu        sync.RWMutex
	proxyIndex     uint64
	proxyClientCache sync.Map
	proxyDeadCount sync.Map
)
type simpleCookieJar struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}
func newCookieJar() *simpleCookieJar {
	return &simpleCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}
}
func (j *simpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := u.Host
	for _, c := range cookies {
		found := false
		for i, existing := range j.cookies[key] {
			if existing.Name == c.Name {
				j.cookies[key][i] = c
				found = true
				break
			}
		}
		if !found {
			j.cookies[key] = append(j.cookies[key], c)
		}
	}
}
func (j *simpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := u.Host
	cookies := j.cookies[key]
	result := make([]*http.Cookie, 0, len(cookies))
	now := time.Now()
	for _, c := range cookies {
		if c.Expires.IsZero() || c.Expires.After(now) {
			result = append(result, c)
		}
	}
	return result
}
func resolveDNS(host string) (string, error) {
	if cached, ok := dnsCache.Load(host); ok {
		entry := cached.(dnsCacheEntry)
		if time.Since(entry.resolvedAt) < DNS_CACHE_TTL {
			return entry.addr, nil
		}
		dnsCache.Delete(host)
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return host, err
	}
	addr := addrs[mrand.Intn(len(addrs))]
	dnsCache.Store(host, dnsCacheEntry{addr: addr, resolvedAt: time.Now()})
	return addr, nil
}
func proxyInit() {
	loadProxies()
}
func loadProxies() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	file, err := os.Open(proxyFile)
	if err != nil {
		return
	}
	defer file.Close()
	var data struct {
		Proxies []string `json:"proxies"`
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				proxyList = append(proxyList, ProxyEntry{Addr: line})
			}
		}
	} else {
		for _, p := range data.Proxies {
			proxyList = append(proxyList, ProxyEntry{Addr: p})
		}
	}
	fmt.Printf("[+] Loaded %d proxies\n", len(proxyList))
}
func refreshProxies() {
	ticker := time.NewTicker(PROXY_HEALTH_INTERVAL * time.Second)
	for range ticker.C {
		if time.Now().After(stopTime) {
			return
		}
		proxyMu.Lock()
		newList := make([]ProxyEntry, 0, len(proxyList))
		for _, p := range proxyList {
			if !p.Dead || p.FailCount < 5 {
				newList = append(newList, p)
			}
		}
		proxyList = newList
		for i := range proxyList {
			proxyList[i].FailCount = 0
			proxyList[i].Dead = false
		}
		proxyMu.Unlock()
		proxyClientCache = sync.Map{}
		fmt.Printf("[PROXY] Refreshed: %d alive\n", len(proxyList))
	}
}
func proxyHealthChecker() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		if time.Now().After(stopTime) {
			return
		}
		proxyMu.Lock()
		alive := 0
		dead := 0
		for i := range proxyList {
			if proxyList[i].Dead {
				dead++
			} else {
				alive++
			}
		}
		proxyMu.Unlock()
		fmt.Printf("[PROXY HEALTH] Alive: %d | Dead: %d | Total: %d\n", alive, dead, alive+dead)
	}
}
func getNextProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	if len(proxyList) == 0 {
		return ""
	}
	aliveProxies := make([]ProxyEntry, 0, len(proxyList))
	for _, p := range proxyList {
		if !p.Dead && p.FailCount < MAX_PROXY_RETRIES {
			aliveProxies = append(aliveProxies, p)
		}
	}
	if len(aliveProxies) == 0 {
		proxyMu.RUnlock()
		proxyMu.Lock()
		for i := range proxyList {
			proxyList[i].FailCount = 0
			proxyList[i].Dead = false
		}
		aliveProxies = proxyList
		proxyMu.Unlock()
		proxyMu.RLock()
	}
	idx := atomic.AddUint64(&proxyIndex, 1)
	return aliveProxies[idx%uint64(len(aliveProxies))].Addr
}
func markProxyDead(addr string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for i := range proxyList {
		if proxyList[i].Addr == addr {
			proxyList[i].FailCount++
			if proxyList[i].FailCount >= MAX_PROXY_RETRIES {
				proxyList[i].Dead = true
			}
			break
		}
	}
}
func markProxySuccess(addr string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for i := range proxyList {
		if proxyList[i].Addr == addr {
			proxyList[i].SuccessCount++
			proxyList[i].FailCount = 0
			break
		}
	}
}
func getProxyClient(addr string) *http.Client {
	if addr == "" {
		return httpClient
	}
	if cached, ok := proxyClientCache.Load(addr); ok {
		return cached.(*http.Client)
	}
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		return httpClient
	}
	proxyTransport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   MAX_CONNS_PER_HOST,
		MaxConnsPerHost:       MAX_CONNS_PER_HOST,
		IdleConnTimeout:       60 * time.Second,
		TLSClientConfig:       getChromeTLSConfig(),
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
	client := &http.Client{
		Transport: proxyTransport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: newCookieJar(),
	}
	proxyClientCache.Store(addr, client)
	return client
}
