package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/songgao/water"
)

// cleanupFunc引数を追加
func runClient(iface *water.Interface, serverAddr string, numLines int, fragSize int, weightStr string, ifaceStr string, cleanupFunc func()) {
	manualWeights := make([]int, numLines)
	wParts := strings.Split(weightStr, ",")
	for i := 0; i < numLines; i++ {
		manualWeights[i] = 10
		if i < len(wParts) {
			fmt.Sscanf(wParts[i], "%d", &manualWeights[i])
		}
	}

	bindIfaces := strings.Split(ifaceStr, ",")
	conns := make([]*ConnectionWrapper, numLines)
	packetIngress := make(chan Packet, 1000)

	successCount := 0

	for i := 0; i < numLines; i++ {
		dialer := net.Dialer{Timeout: 5 * time.Second} // タイムアウトを少し短く
		if i < len(bindIfaces) && strings.TrimSpace(bindIfaces[i]) != "" {
			targetIface := strings.TrimSpace(bindIfaces[i])
			if localAddr, err := resolveInterfaceIP(targetIface); err == nil {
				dialer.LocalAddr = localAddr
				log.Printf("[Line %d] Bind: %s (%s)", i, targetIface, localAddr.String())
			} else {
				log.Printf("[Line %d] Bind Error: %v (Trying default)", i, err)
			}
		}

		c, err := dialer.Dial("tcp", serverAddr)
		if err != nil {
			// エラーでも続行 (Robust Dialing)
			log.Printf("[Line %d] Connect Failed: %v", i, err)
			continue
		}

		if err := clientHandshake(c); err != nil {
			log.Printf("[Line %d] Handshake Failed: %v", i, err)
			c.Close()
			continue
		}

		log.Printf("[Line %d] Connected.", i)
		successCount++

		cw := &ConnectionWrapper{
			ID: i, Conn: c, Enc: gob.NewEncoder(c), Alive: true, BaseWeight: manualWeights[i], RTT: 100 * time.Millisecond,
		}
		conns[i] = cw

		go func(w *ConnectionWrapper) {
			dec := gob.NewDecoder(w.Conn)
			for {
				var pkt Packet
				if err := dec.Decode(&pkt); err != nil {
					log.Printf("Line %d disconnected: %v", w.ID, err)
					w.Mu.Lock()
					w.Alive = false
					w.Mu.Unlock()
					return
				}
				if pkt.Type == TypePong {
					rtt := time.Since(time.Unix(0, pkt.Timestamp))
					w.Mu.Lock()
					w.RTT = rtt
					w.Alive = true
					w.Mu.Unlock()
				} else {
					packetIngress <- pkt
				}
			}
		}(cw)

		go func(w *ConnectionWrapper) {
			for range time.Tick(KeepAliveInterval) {
				if !w.Alive {
					return
				}
				p := Packet{Type: TypePing, Timestamp: time.Now().UnixNano()}
				w.Mu.Lock()
				w.Enc.Encode(p)
				w.Mu.Unlock()
			}
		}(cw)
	}

	// 全回線失敗なら終了
	if successCount == 0 {
		log.Println("All connections failed. Exiting.")
		if cleanupFunc != nil {
			cleanupFunc()
		}
		os.Exit(1)
	}

	go networkToTunLoop(iface, packetIngress)
	tunToNetworkLoop(iface, conns, fragSize)
}