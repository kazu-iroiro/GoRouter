package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sort"
	"time"

	"github.com/songgao/water"
)

// TUN -> Network
func tunToNetworkLoop(iface *water.Interface, conns []*ConnectionWrapper, fragSize int) {
	packet := make([]byte, TunReadSize)
	log.Println("Started TUN Reader Loop")

	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatalf("TUN read error: %v", err)
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
			// --- SeqID Wrap-around Logic ---
			if globalSeqID == MaxSeqID {
				globalSeqID = 0
				log.Println("[INFO] SeqID reached limit. Wrapping around to 0.")
			} else {
				globalSeqID++
			}
			currentSeq := globalSeqID
			seqMu.Unlock()
			// -------------------------------

			pkt := Packet{
				Type:    TypeData,
				SeqID:   currentSeq,
				Payload: chunk,
				IsFin:   isLast,
			}

			if err := sendPacketWeighted(conns, pkt); err != nil {
				debugLog("Drop/Fail Seq:%d: %v", currentSeq, err)
			}
			offset = end
		}
	}
}

// Network -> TUN (Timeoutによる自動復旧機能付き)
func networkToTunLoop(iface *water.Interface, pktChan <-chan Packet) {
	var nextSeqID int64 = 0
	var initialized bool = false
	buffer := make(map[int64]Packet)
	var ipPacketBuffer bytes.Buffer

	log.Println("Started Network Reassembler Loop")

	// パケット処理関数
	processPacket := func(pkt Packet) {
		if pkt.Type != TypeData {
			return
		}
		ipPacketBuffer.Write(pkt.Payload)
		if pkt.IsFin {
			data := ipPacketBuffer.Bytes()
			if _, err := iface.Write(data); err != nil {
				log.Printf("TUN write error: %v", err)
			} else {
				debugLog("TUN Write: %d bytes (Seq:%d)", len(data), pkt.SeqID)
			}
			ipPacketBuffer.Reset()
		}
	}

	// タイムアウト監視用のTicker
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	lastProgressTime := time.Now()

	for {
		select {
		case pkt := <-pktChan:
			lastProgressTime = time.Now()

			// リセット検出
			if pkt.SeqID == 0 {
				log.Println("[INFO] SeqID Reset detected. Clearing.")
				nextSeqID = 0
				buffer = make(map[int64]Packet)
				ipPacketBuffer.Reset()
				initialized = true
			}

			if !initialized {
				log.Printf("[INFO] Initializing SeqID: %d", pkt.SeqID)
				nextSeqID = pkt.SeqID
				initialized = true
			}

			if pkt.SeqID == nextSeqID {
				processPacket(pkt)
				nextSeqID++
				// バッファ消化
				for {
					if nextPkt, ok := buffer[nextSeqID]; ok {
						delete(buffer, nextSeqID)
						processPacket(nextPkt)
						nextSeqID++
					} else {
						break
					}
				}
			} else if pkt.SeqID > nextSeqID {
				debugLog("Buffered Seq:%d (Want %d)", pkt.SeqID, nextSeqID)
				buffer[pkt.SeqID] = pkt
			}
			// 古いパケットは無視

		case <-ticker.C:
			// スタック検知：バッファに未来のパケットがあるのに、現在待ちのSeqIDが来ない
			if len(buffer) > 0 && time.Since(lastProgressTime) > StallTimeout {
				// バッファ内で最小のSeqIDを探す
				var minBufferedSeq int64 = -1
				var keys []int64
				for k := range buffer {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

				if len(keys) > 0 {
					minBufferedSeq = keys[0]
				}

				if minBufferedSeq != -1 && minBufferedSeq > nextSeqID {
					log.Printf("[WARN] Stall detected! Skipping missing packets %d -> %d", nextSeqID, minBufferedSeq)
					// 強制スキップ。組み立て中のバッファは壊れているので破棄
					ipPacketBuffer.Reset()
					nextSeqID = minBufferedSeq
					lastProgressTime = time.Now() // タイマーリセット

					// スキップ先にバッファがあれば処理再開
					for {
						if nextPkt, ok := buffer[nextSeqID]; ok {
							delete(buffer, nextSeqID)
							processPacket(nextPkt)
							nextSeqID++
						} else {
							break
						}
					}
				}
			}
		}
	}
}

func sendPacketWeighted(conns []*ConnectionWrapper, pkt Packet) error {
	type Candidate struct {
		C     *ConnectionWrapper
		Score float64
	}
	var candidates []Candidate
	var totalScore float64

	for _, c := range conns {
		if c == nil {
			continue
		} // 接続失敗したLineはnilの可能性あり
		c.Mu.Lock()
		alive := c.Alive
		rtt := c.RTT
		bw := c.BaseWeight
		c.Mu.Unlock()

		if !alive {
			continue
		}
		ms := float64(rtt.Milliseconds())
		if ms <= 0 {
			ms = 1
		}
		score := float64(bw) * (100.0 / ms)
		candidates = append(candidates, Candidate{c, score})
		totalScore += score
	}

	if len(candidates) == 0 {
		return fmt.Errorf("no active lines")
	}

	r, _ := rand.Int(rand.Reader, big.NewInt(1000))
	randVal := float64(r.Int64()) / 1000.0 * totalScore

	var target *ConnectionWrapper
	current := 0.0
	for _, cand := range candidates {
		current += cand.Score
		if randVal < current {
			target = cand.C
			break
		}
	}
	if target == nil {
		target = candidates[len(candidates)-1].C
	}

	target.Mu.Lock()
	err := target.Enc.Encode(pkt)
	target.Mu.Unlock()

	if err == nil {
		debugLog("Sent Seq:%d Size:%d via Line %d", pkt.SeqID, len(pkt.Payload), target.ID)
	}

	return err
}