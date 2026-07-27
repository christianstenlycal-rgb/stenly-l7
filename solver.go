package main
import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type CFChallengeResult struct {
	Success     bool
	CfClearance string
	CfBm        string
	UserAgent   string
	SolvedBy    string
	Error       string
}
type BrowserFingerprint struct {
	CanvasHash    string  `json:"canvas"`
	WebGLVendor   string  `json:"webglVendor"`
	WebGLRenderer string  `json:"webglRenderer"`
	Platform      string  `json:"platform"`
	Language      string  `json:"language"`
	ScreenW       int     `json:"screenW"`
	ScreenH       int     `json:"screenH"`
	ColorDepth    int     `json:"colorDepth"`
	PixelRatio    float64 `json:"pixelRatio"`
	HardwareConc  int     `json:"hardwareConcurrency"`
	DeviceMemory  int     `json:"deviceMemory"`
	UserAgent     string  `json:"userAgent"`
	Timestamp     int64   `json:"timestamp"`
}
type cfCookieStore struct {
	mu      sync.RWMutex
	cookies map[string]*cfClearanceEntry
}
type cfClearanceEntry struct {
	clearance string
	cfBm      string
	userAgent string
	expiresAt time.Time
}
type cfChallengeParams struct {
	RayID      string
	Salt       string
	Difficulty int
	Mode       int
	Challenge  string
	SType      string
	ScriptSrc  string
}

var cfStore = &cfCookieStore{
	cookies: make(map[string]*cfClearanceEntry),
}
func (s *cfCookieStore) Get(host string) *cfClearanceEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.cookies[host]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry
}
func (s *cfCookieStore) Set(host, clearance, cfBm, userAgent string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clearance == "" && cfBm == "" {
		return
	}
	s.cookies[host] = &cfClearanceEntry{
		clearance: clearance,
		cfBm:      cfBm,
		userAgent: userAgent,
		expiresAt: time.Now().Add(CF_CLEARANCE_TTL),
	}
}

func isCFChallenge(resp *http.Response, body []byte) bool {
	if resp.StatusCode != 403 && resp.StatusCode != 503 {
		return false
	}
	bodyStr := string(body)
	return strings.Contains(bodyStr, "__CF$cv$params") ||
		strings.Contains(bodyStr, "challenge-platform") ||
		strings.Contains(bodyStr, "Just a moment") ||
		strings.Contains(bodyStr, "Checking your browser") ||
		strings.Contains(bodyStr, "cf-challenge") ||
		strings.Contains(bodyStr, "jsd/main.js") ||
		strings.Contains(bodyStr, "cf-turnstile") ||
		strings.Contains(bodyStr, "cf-error")
}

func extractChallengeParam(body []byte, param string) string {
	patterns := []string{
		fmt.Sprintf(`(?:var\s+)?%s\s*=\s*["']([^"']+)["']`, param),
		fmt.Sprintf(`%s\s*:\s*["']([^"']+)["']`, param),
		fmt.Sprintf(`"%s"\s*:\s*["']([^"']+)["']`, param),
		fmt.Sprintf(`%s\s*=\s*["']([^"']+)["']`, param),
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			return string(matches[1])
		}
	}
	return ""
}

func extractScriptURL(body []byte) string {
	patterns := []string{
		`["'](/cdn-cgi/challenge-platform/[^"']+\.js)["']`,
		`src\s*=\s*["']([^"']*challenge-platform[^"']*\.js)["']`,
		`["'](https?://[^"']*challenge-platform[^"']*\.js)["']`,
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			return string(matches[1])
		}
	}
	return ""
}

func extractCFParams(body []byte) *cfChallengeParams {
	params := &cfChallengeParams{}
	bodyStr := string(body)

	scriptRe := regexp.MustCompile(`<script[^>]*src=["']([^"']*challenge-platform[^"']*\.js)["']`)
	if m := scriptRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		params.ScriptSrc = m[1]
	}

	rayRe := regexp.MustCompile(`(?i)(?:data-ray|ray)\s*[=:]\s*["']?([a-f0-9]{16,})["']?`)
	if m := rayRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		params.RayID = m[1]
	}
	rayRe2 := regexp.MustCompile(`(?i)[?&]ray\s*=\s*([a-f0-9]{16,})`)
	if m := rayRe2.FindStringSubmatch(bodyStr); len(m) > 1 {
		params.RayID = m[1]
	}

	variables := []string{"s", "ct", "ch", "cType", "cN", "cS", "cL", "difficulty"}
	values := make(map[string]string)
	for _, v := range variables {
		values[v] = extractChallengeParam(body, v)
	}
	if values["s"] != "" {
		params.Salt = values["s"]
	}
	if values["difficulty"] != "" {
		fmt.Sscanf(values["difficulty"], "%d", &params.Difficulty)
	}
	if values["ch"] != "" {
		params.Challenge = values["ch"]
	}
	params.SType = values["cType"]

	cfRe := regexp.MustCompile(`cType['"]?\s*[:=]\s*['"]([^'"]+)['"]`)
	if m := cfRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		params.SType = m[1]
	}

	if params.Difficulty <= 0 {
		difficultyRe := regexp.MustCompile(`difficulty["']?\s*[:=]\s*["']?(\d+)["']?`)
		if m := difficultyRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			fmt.Sscanf(m[1], "%d", &params.Difficulty)
		}
	}
	if params.Difficulty <= 0 {
		params.Difficulty = 4
	}

	cfParamsRe := regexp.MustCompile(`_cf_chl_opt\s*=\s*({[^;]+})`)
	if m := cfParamsRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		raw := m[1]
		sRe := regexp.MustCompile(`["']s["']\s*:\s*["']([^"']+)["']`)
		if sm := sRe.FindStringSubmatch(raw); len(sm) > 1 && params.Salt == "" {
			params.Salt = sm[1]
		}
		rRe := regexp.MustCompile(`["']cRay["']\s*:\s*["']([^"']+)["']`)
		if rm := rRe.FindStringSubmatch(raw); len(rm) > 1 && params.RayID == "" {
			params.RayID = rm[1]
		}
		mRe := regexp.MustCompile(`["']cTplV["']\s*:\s*(\d+)`)
		if mm := mRe.FindStringSubmatch(raw); len(mm) > 1 {
			fmt.Sscanf(mm[1], "%d", &params.Mode)
		}
	}

	cfParamsRe2 := regexp.MustCompile(`__CF\$cv\$params\s*=\s*({[^;]+})`)
	if m := cfParamsRe2.FindStringSubmatch(bodyStr); len(m) > 1 {
		raw := m[1]
		sRe := regexp.MustCompile(`["']s["']\s*:\s*["']([^"']+)["']`)
		if sm := sRe.FindStringSubmatch(raw); len(sm) > 1 && params.Salt == "" {
			params.Salt = sm[1]
		}
		rRe := regexp.MustCompile(`["']r["']\s*:\s*["']([^"']+)["']`)
		if rm := rRe.FindStringSubmatch(raw); len(rm) > 1 && params.RayID == "" {
			params.RayID = rm[1]
		}
		mRe := regexp.MustCompile(`["']m["']\s*:\s*["']?(\d+)["']?`)
		if mm := mRe.FindStringSubmatch(raw); len(mm) > 1 {
			fmt.Sscanf(mm[1], "%d", &params.Mode)
		}
	}

	if params.RayID == "" {
		rRe := regexp.MustCompile(`cRay['"]?\s*[:=]\s*['"]([a-f0-9]{16,})['"]`)
		if m := rRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			params.RayID = m[1]
		}
	}
	if params.RayID == "" {
		rRe := regexp.MustCompile(`[?&]r[=:]([a-f0-9]{16,})`)
		if m := rRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			params.RayID = m[1]
		}
	}

	return params
}

func solveJSDChallenge(targetURL string, client *http.Client, ua string, proxyAddr string) *CFChallengeResult {
	result := &CFChallengeResult{UserAgent: ua}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Error = "invalid URL"
		return result
	}
	siteURL := parsedURL.Scheme + "://" + parsedURL.Host

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == "cf_clearance" {
			result.Success = true
			result.CfClearance = c.Value
			result.SolvedBy = "direct"
			return result
		}
	}
	if !isCFChallenge(resp, body) {
		result.Success = true
		result.SolvedBy = "no-challenge"
		return result
	}

	params := extractCFParams(body)

	if params.SType == "interactive" || params.SType == "non-interactive" {
		result.Error = fmt.Sprintf("Turnstile challenge (%s) — JSD solver cannot handle, needs browser", params.SType)
		fmt.Printf("[CF] %s\n", result.Error)
		return result
	}

	if params.RayID == "" {
		result.Error = "could not extract ray ID"
		return result
	}
	if params.Salt == "" && params.SType == "" {
		saltRe := regexp.MustCompile(`["']s["']\s*[:=]\s*["']([^"']+)["']`)
		if m := saltRe.FindSubmatch(body); len(m) > 1 {
			params.Salt = string(m[1])
		}
	}
	if params.Salt == "" {
		result.Error = "could not extract challenge salt"
		return result
	}

	fmt.Printf("[JSD] Challenge detected: ray=%s salt=%s... difficulty=%d\n",
		params.RayID, params.Salt[:min(len(params.Salt), 8)], params.Difficulty)

	var nonce uint64
	maxNonce := uint64(1) << 48
	startNonce := uint64(mrand.Int63n(int64(maxNonce / 100)))
	if startNonce < 1000 {
		startNonce = 1000
	}

	solved := false
	var solution uint64
	challengeTimeout := time.Now().Add(10 * time.Second)

	saltBytes := []byte(params.Salt)
	var hashPrefix string
	for i := 0; i < params.Difficulty; i++ {
		hashPrefix += "0"
	}

	for nonce = startNonce; nonce < maxNonce; nonce++ {
		if time.Now().After(challengeTimeout) {
			break
		}
		nonceStr := fmt.Sprintf("%d", nonce)
		data := append(saltBytes, []byte(nonceStr)...)
		var hashStr string
		if params.Mode == 2 || params.Challenge != "" {
			h := sha256.Sum256(data)
			hashStr = hex.EncodeToString(h[:])
		} else {
			h := md5.Sum(data)
			hashStr = hex.EncodeToString(h[:])
		}
		if strings.HasPrefix(hashStr, hashPrefix) {
			solved = true
			solution = nonce
			break
		}

	}

	if !solved {
		result.Error = "PoW failed: could not find valid nonce"
		return result
	}

	fmt.Printf("[JSD] PoW solved! nonce=%d\n", solution)

	solveURL := fmt.Sprintf("%s/cdn-cgi/challenge-platform/h/b/ov1/%s", siteURL, params.RayID)
	payload := map[string]interface{}{
		"r":      params.RayID,
		"md":     fmt.Sprintf("%d", solution),
		"m":      params.Mode,
		"s":      params.Salt,
		"v":      "1",
		"cD":     mrand.Intn(100),
		"cM":     fmt.Sprintf("%d", time.Now().UnixMilli()),
		"cT":     fmt.Sprintf("%d", time.Now().UnixMilli()),
	}
	if params.Challenge != "" {
		payload["ch"] = params.Challenge
	}
	payloadJSON, _ := json.Marshal(payload)

	solReq, _ := http.NewRequest("POST", solveURL, bytes.NewReader(payloadJSON))
	solReq.Header.Set("Content-Type", "application/json")
	solReq.Header.Set("User-Agent", ua)
	solReq.Header.Set("Origin", siteURL)
	solReq.Header.Set("Referer", targetURL)
	solReq.Header.Set("Accept", "*/*")
	solReq.Header.Set("Sec-Fetch-Site", "same-origin")
	solReq.Header.Set("Sec-Fetch-Mode", "cors")
	solReq.Header.Set("Sec-Fetch-Dest", "empty")
	solReq.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`)
	solReq.Header.Set("Sec-CH-UA-Mobile", "?0")
	solReq.Header.Set("Sec-CH-UA-Platform", `"Windows"`)

	solResp, err := client.Do(solReq)
	if err != nil {
		result.Error = "submit error: " + err.Error()
		return result
	}
	defer solResp.Body.Close()

	submitBody, _ := io.ReadAll(solResp.Body)

	for _, c := range solResp.Cookies() {
		if c.Name == "cf_clearance" {
			result.Success = true
			result.CfClearance = c.Value
			result.SolvedBy = "jsd-pow"
			return result
		}
		if c.Name == "__cf_bm" {
			result.CfBm = c.Value
		}
	}

	if len(solResp.Cookies()) == 0 {
		solBodyStr := string(submitBody)
		fmt.Printf("[JSD] Submit response (no cookie): %d %s\n", solResp.StatusCode, solBodyStr[:min(len(solBodyStr), 200)])

		finalReq, _ := http.NewRequest("GET", targetURL, nil)
		finalReq.Header.Set("User-Agent", ua)
		finalReq.Header.Set("Accept", "text/html,*/*")
		finalReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
		finalResp, err := client.Do(finalReq)
		if err != nil {
			result.Error = "verify error: " + err.Error()
			return result
		}
		defer finalResp.Body.Close()
		io.Copy(io.Discard, finalResp.Body)

		for _, c := range finalResp.Cookies() {
			if c.Name == "cf_clearance" {
				result.Success = true
				result.CfClearance = c.Value
				result.SolvedBy = "jsd-pow-verify"
				return result
			}
		}
	}

	if result.CfBm != "" {
		result.Success = true
		result.SolvedBy = "jsd-pow-bmonly"
		return result
	}

	if solResp.StatusCode >= 200 && solResp.StatusCode < 400 {
		result.Success = true
		result.CfClearance = "solved_nonce_" + fmt.Sprintf("%d", solution)
		result.SolvedBy = "jsd-pow-fallback"
		return result
	}

	result.Error = fmt.Sprintf("submit failed: status=%d body=%s", solResp.StatusCode, string(submitBody[:min(len(submitBody), 100)]))
	return result
}

func solveViaAPISolver(targetURL string, ua string) *CFChallengeResult {
	result := &CFChallengeResult{UserAgent: ua}
	if cfg.cfSolverAPI == "" {
		result.Error = "no solver API configured"
		return result
	}

	apiURL := fmt.Sprintf("%s?url=%s&ua=%s", cfg.cfSolverAPI, url.QueryEscape(targetURL), url.QueryEscape(ua))
	apiReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		result.Error = "api request error: " + err.Error()
		return result
	}
	apiReq.Header.Set("Accept", "application/json")

	apiClient := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		},
	}
	apiResp, err := apiClient.Do(apiReq)
	if err != nil {
		result.Error = "api call error: " + err.Error()
		return result
	}
	defer apiResp.Body.Close()

	apiBody, _ := io.ReadAll(apiResp.Body)
	var apiResult struct {
		Success     bool               `json:"success"`
		CfClearance string             `json:"cf_clearance"`
		CfBm        string             `json:"cf_bm"`
		UserAgent   string             `json:"user_agent"`
		Cookies     []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
		} `json:"cookies"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(apiBody, &apiResult); err != nil {
		result.Error = "api parse error: " + err.Error()
		return result
	}
	if !apiResult.Success {
		result.Error = "api: " + apiResult.Error
		return result
	}

	result.Success = true
	result.CfClearance = apiResult.CfClearance
	result.CfBm = apiResult.CfBm
	if apiResult.UserAgent != "" {
		result.UserAgent = apiResult.UserAgent
	}
	result.SolvedBy = "api-solver"
	return result
}

func makeSolverClient(proxyAddr string) *http.Client {
	if proxyAddr != "" {
		return getProxyClient(proxyAddr)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				ClientSessionCache: tls.NewLRUClientSessionCache(64),
				NextProtos:         []string{"h2", "http/1.1"},
			},
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
		},
		Timeout: 45 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: newCookieJar(),
	}
}

func solveCFChallenge(targetURL string, cfClient *http.Client, ua string, proxyAddr string) *CFChallengeResult {
	result := &CFChallengeResult{UserAgent: ua}

	if cfg.cfClearance != "" && cfStore.Get(cfg.targetHost) != nil {
		entry := cfStore.Get(cfg.targetHost)
		result.Success = true
		result.CfClearance = entry.clearance
		result.CfBm = entry.cfBm
		result.UserAgent = entry.userAgent
		result.SolvedBy = "pre-solved"
		return result
	}

	client := makeSolverClient(proxyAddr)

	result = solveJSDChallenge(targetURL, client, ua, proxyAddr)
	if result.Success && result.CfClearance != "" {
		cfStore.Set(cfg.targetHost, result.CfClearance, result.CfBm, result.UserAgent)
		return result
	}

	isTurnstile := strings.Contains(result.Error, "Turnstile")
	isPoW := strings.Contains(result.Error, "PoW")
	isConn := strings.Contains(result.Error, "timeout") || strings.Contains(result.Error, "TLS")

	if isTurnstile || (isConn && cfg.cfSolverAPI != "") {
		fmt.Printf("[CF] %s, trying API solver...\n", result.Error)
		apiResult := solveViaAPISolver(targetURL, ua)
		if apiResult.Success {
			cfStore.Set(cfg.targetHost, apiResult.CfClearance, apiResult.CfBm, apiResult.UserAgent)
			return apiResult
		}
		fmt.Printf("[CF] API solver also failed: %s\n", apiResult.Error)
		return apiResult
	}

	if isPoW {
		for attempt := 0; attempt < 2; attempt++ {
			fmt.Printf("[CF] JSD retry (attempt %d/2): %s\n", attempt+1, result.Error)
			time.Sleep(time.Duration(500+attempt*500) * time.Millisecond)
			result = solveJSDChallenge(targetURL, client, ua, proxyAddr)
			if result.Success && result.CfClearance != "" {
				cfStore.Set(cfg.targetHost, result.CfClearance, result.CfBm, result.UserAgent)
				return result
			}
			if !strings.Contains(result.Error, "PoW") {
				break
			}
		}
	}

	return result
}

type utlsRoundTripper struct {
	dialer *net.Dialer
}
func newUTLSRoundTripper() *utlsRoundTripper {
	return &utlsRoundTripper{
		dialer: &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		},
	}
}
func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	var rawConn net.Conn
	var err error
	addr := net.JoinHostPort(host, port)
	rawConn, err = rt.dialer.Dial("tcp", addr)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			if strings.Contains(addr, ":") && !strings.Contains(addr, ".") {
				ipv4, v4err := net.ResolveIPAddr("ip4", host)
				if v4err == nil {
					rawConn, err = rt.dialer.Dial("tcp", net.JoinHostPort(ipv4.String(), port))
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}
	uc := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	if err := uc.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	if uc.ConnectionState().NegotiatedProtocol == "h2" {
		cc, err := (&http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return uc, nil
			},
		}).NewClientConn(uc)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			cc.Close()
			return nil, err
		}
		return resp, nil
	}
	if err := req.Write(uc); err != nil {
		rawConn.Close()
		return nil, err
	}
	br := bufio.NewReader(uc)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	resp.Body = &readCloser{br, uc}
	return resp, nil
}
func newUTLSHTTPClient() *http.Client {
	return &http.Client{
		Transport: newUTLSRoundTripper(),
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Jar: newCookieJar(),
	}
}


