package main

import (
	"encoding/gob"
	"log"
	"net"
	"sync"
	"time"

	"github.com/songgao/water"
)

func runServer(iface *water.Interface, addr string, fragSize int) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	log.Printf("[Server] Listening on %s", addr)

	packetIngress := make(chan Packet, 1000)
	var clients []*ConnectionWrapper
	var clientsMu sync.Mutex

	go networkToTunLoop(iface, packetIngress)

	go func() {
		packet := make([]byte, TunReadSize)
		for {
			n, err := iface.Read(packet)
			if err != nil {
				log.Fatal(err)
			}

			rawData := packet[:n]
			offset := 0
			for offset < n {
				end := offset + fragSize
				isLast := false
				if end >= n {
					end = n
					isLast = true
				}

				chunk := make([]byte, end-offset)
				copy(chunk, rawData[offset:end])

				seqMu.Lock()
				currentSeq := globalSeqID
				globalSeqID++
				seqMu.Unlock()

				pkt := Packet{Type: TypeData, SeqID: currentSeq, Payload: chunk, IsFin: isLast}

				clientsMu.Lock()
				if len(clients) > 0 {
					sendPacketWeighted(clients, pkt)
				}
				clientsMu.Unlock()

				offset = end
			}
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			if err := serverHandshake(c); err != nil {
				log.Printf("[Auth Failed] %v", err)
				c.Close()
				return
			}
			log.Printf("[Auth Success] Client: %s", c.RemoteAddr())

			wrapper := &ConnectionWrapper{
				Conn: c, Enc: gob.NewEncoder(c), Alive: true, BaseWeight: 10, RTT: 10 * time.Millisecond,
			}

			clientsMu.Lock()
			wrapper.ID = len(clients)
			clients = append(clients, wrapper)
			clientsMu.Unlock()

			dec := gob.NewDecoder(c)
			for {
				var pkt Packet
				if err := dec.Decode(&pkt); err != nil {
					log.Printf("Client disconnected: %v", err)
					wrapper.Mu.Lock()
					wrapper.Alive = false
					wrapper.Mu.Unlock()
					return
				}
				if pkt.Type == TypePing {
					go func(p Packet) {
						pong := Packet{Type: TypePong, Timestamp: p.Timestamp}
						wrapper.Mu.Lock()
						wrapper.Enc.Encode(pong)
						wrapper.Mu.Unlock()
					}(pkt)
				} else {
					packetIngress <- pkt
				}
			}
		}(conn)
	}
}