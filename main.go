package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// --- 設定・定数 ---

const (
	ProtocolVersion   = "BOND/2.2"
	ChallengeSize     = 32
	KeepAliveInterval = 60 * time.Second
)

// PacketType 定義
type PacketType int

const (
	TypeData PacketType = iota
	TypePing
	TypePong
	TypeFin // 送信完了を示すパケットタイプ
)

// Packet はネットワークを流れるデータの単位
type Packet struct {
	Type      PacketType
	SeqID     int64
	Payload   []byte
	Timestamp int64 // RTT計測用 (UnixNano)
}

// HandshakeMsg 認証用メッセージ
type HandshakeMsg struct {
	PublicKey []byte
	Signature []byte
}

// --- グローバル変数（鍵管理） ---
var (
	serverPrivKey *rsa.PrivateKey
	clientPrivKey *rsa.PrivateKey
)

func init() {
	var err error
	serverPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	clientPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	mode := flag.String("mode", "server", "Mode: server or client")
	addr := flag.String("addr", "localhost:8080", "Server address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	mtu := flag.Int("mtu", 100, "Max Transfer Unit size (Client mode only)")
	weights := flag.String("weights", "", "Comma separated weights (e.g. '10,1').")
	flag.Parse()

	if *mode == "server" {
		runServer(*addr)
	} else {
		runClient(*addr, *lines, *mtu, *weights)
	}
}

// ==========================================
// サーバー側実装 (再構成・集約)
// ==========================================

func runServer(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server listen error: %v", err)
	}
	log.Printf("[Server] Listening on %s", addr)

	packetStream := make(chan Packet, 1000)

	go aggregator(packetStream)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleServerConnection(conn, packetStream)
	}
}

func handleServerConnection(conn net.Conn, out chan<- Packet) {
	defer conn.Close()

	// --- 認証フェーズ ---
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	dec := gob.NewDecoder(conn)
	var authMsg HandshakeMsg
	if err := dec.Decode(&authMsg); err != nil {
		return
	}

	pubKey, err := parsePublicKey(authMsg.PublicKey)
	if err != nil {
		return
	}

	hashed := sha256.Sum256(challenge)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], authMsg.Signature); err != nil {
		log.Printf("[Server] Auth Failed: %s", conn.RemoteAddr())
		return
	}
	log.Printf("[Server] Auth Success: %s", conn.RemoteAddr())

	// --- 送信エンコーダー (Pong返信用) ---
	enc := gob.NewEncoder(conn)
	encMu := &sync.Mutex{}

	// --- データ受信ループ ---
	for {
		var pkt Packet
		if err := dec.Decode(&pkt); err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		switch pkt.Type {
		case TypePing:
			go func(p Packet) {
				pong := Packet{Type: TypePong, Timestamp: p.Timestamp}
				encMu.Lock()
				enc.Encode(pong)
				encMu.Unlock()
			}(pkt)
		case TypeData, TypeFin: // FINパケットも集約チャネルへ流す
			out <- pkt
		}
	}
}

// aggregator はパケットを順序通りに再構成し、リアルタイムに内容を表示します
func aggregator(in <-chan Packet) {
	log.Println("[Server] Aggregator started. Ready to reassemble.")

	var nextSeqID int64 = 0
	buffer := make(map[int64]Packet)
	var assembledData bytes.Buffer // 全データ蓄積用バッファ

	// パケット処理ロジック
	processPacket := func(pkt Packet) {
		if pkt.Type == TypeData {
			// データパケット: バッファに書き込み
			assembledData.Write(pkt.Payload)
			
			// 個別ログ出力 (SeqIDなどのメタデータ確認用)
			printPacket(pkt)

			// ★修正点: 受信データをリアルタイムで表示
			fmt.Printf("\n--- [Current Content (Total: %d bytes)] ---\n%s\n-------------------------------------------\n", 
				assembledData.Len(), assembledData.String())

		} else if pkt.Type == TypeFin {
			// 完了パケット: 最終確認ログ
			log.Println("\n========================================")
			log.Printf("[Result] FIN received! (Last SeqID: %d)", pkt.SeqID)
			log.Printf("[Result] Final Content:\n%s", assembledData.String())
			log.Println("========================================")

			// セッションリセット
			assembledData.Reset()
			nextSeqID = -1 
		}
	}

	for pkt := range in {
		// 簡易セッションリセット検出
		if pkt.SeqID == 0 && nextSeqID != 0 {
			log.Println("[Server] Detected new session (SeqID=0). Resetting state.")
			nextSeqID = 0
			assembledData.Reset()
			buffer = make(map[int64]Packet)
		}

		if pkt.SeqID == nextSeqID {
			// 期待通りの順番
			processPacket(pkt)
			nextSeqID++

			// バッファ内の後続パケットを確認
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
			// 未来のパケット -> 一時保存
			buffer[pkt.SeqID] = pkt
		}
	}
}

func printPacket(pkt Packet) {
	fmt.Printf("[Output] Seq:%d | Size:%d | Payload: %s\n",
		pkt.SeqID, len(pkt.Payload), string(pkt.Payload))
}

// ==========================================
// クライアント側実装
// ==========================================

type ClientLine struct {
	ID         int
	Conn       net.Conn
	Enc        *gob.Encoder
	Mu         sync.Mutex
	Alive      bool
	RTT        time.Duration
	BaseWeight int
}

func runClient(serverAddr string, numLines int, mtu int, weightStr string) {
	log.Printf("[Client] MTU: %d, Weights: %s", mtu, weightStr)

	manualWeights := make([]int, numLines)
	wParts := strings.Split(weightStr, ",")
	for i := 0; i < numLines; i++ {
		manualWeights[i] = 10
		if i < len(wParts) {
			if _, err := fmt.Sscanf(wParts[i], "%d", &manualWeights[i]); err != nil {
				manualWeights[i] = 10
			}
		}
	}

	lines := make([]*ClientLine, numLines)
	var wg sync.WaitGroup

	for i := 0; i < numLines; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Fatalf("Dial failed for line %d: %v", i, err)
		}

		if err := performClientHandshake(conn); err != nil {
			log.Fatalf("Handshake failed line %d: %v", i, err)
		}

		line := &ClientLine{
			ID:         i,
			Conn:       conn,
			Enc:        gob.NewEncoder(conn),
			Alive:      true,
			RTT:        100 * time.Millisecond,
			BaseWeight: manualWeights[i],
		}
		lines[i] = line

		wg.Add(1)
		go monitorLine(line, &wg)
	}

	inputLoop(lines, mtu)

	wg.Wait()
}

func monitorLine(line *ClientLine, wg *sync.WaitGroup) {
	defer wg.Done()

	go func() {
		dec := gob.NewDecoder(line.Conn)
		for {
			var pkt Packet
			if err := dec.Decode(&pkt); err != nil {
				log.Printf("[Line %d] Disconnected: %v", line.ID, err)
				line.Mu.Lock()
				line.Alive = false
				line.Mu.Unlock()
				return
			}
			if pkt.Type == TypePong {
				sentTime := time.Unix(0, pkt.Timestamp)
				rtt := time.Since(sentTime)
				line.Mu.Lock()
				line.RTT = rtt
				line.Alive = true
				line.Mu.Unlock()
			}
		}
	}()

	ticker := time.NewTicker(KeepAliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		line.Mu.Lock()
		if !line.Alive {
			line.Mu.Unlock()
			return
		}

		ping := Packet{
			Type:      TypePing,
			Timestamp: time.Now().UnixNano(),
		}
		err := line.Enc.Encode(ping)
		line.Mu.Unlock()

		if err != nil {
			log.Printf("[Line %d] Ping send failed", line.ID)
		} else {
			log.Printf("[Line %d] Ping sent", line.ID)
		}
	}
}

func inputLoop(lines []*ClientLine, mtu int) {
	scanner := bufio.NewScanner(os.Stdin)
	log.Println("[Client] Ready. Type text to send. (Ctrl+C/D to Finish)")

	var seqID int64 = 0

	for scanner.Scan() {
		rawData := scanner.Bytes()

		offset := 0
		for offset < len(rawData) {
			end := offset + mtu
			if end > len(rawData) {
				end = len(rawData)
			}
			chunk := rawData[offset:end]

			payload := make([]byte, len(chunk))
			copy(payload, chunk)

			pkt := Packet{
				Type:    TypeData,
				SeqID:   seqID,
				Payload: payload,
			}

			sendPacket(lines, pkt)
			seqID++
			offset = end
		}
	}

	// EOF到達後、完了パケット(TypeFin)を送信
	log.Println("[Client] Input ended. Sending FIN packet...")
	finPkt := Packet{
		Type:  TypeFin,
		SeqID: seqID, // 最後のデータ+1 のSeqID
	}
	sendPacket(lines, finPkt)

	// 少し待ってから終了（FINパケットが確実に届くように）
	time.Sleep(500 * time.Millisecond)
	log.Println("[Client] Done.")
	os.Exit(0)
}

func sendPacket(lines []*ClientLine, pkt Packet) {
	targetLine := selectLineWeighted(lines)
	if targetLine != nil {
		targetLine.Mu.Lock()
		err := targetLine.Enc.Encode(pkt)
		targetLine.Mu.Unlock()

		if err != nil {
			log.Printf("Send failed on line %d", targetLine.ID)
		} else {
			if pkt.Type == TypeFin {
				log.Printf("[Sent] FIN Packet Seq:%d via Line %d", pkt.SeqID, targetLine.ID)
			} else {
				log.Printf("[Sent] Seq:%d via Line %d (RTT: %v)", pkt.SeqID, targetLine.ID, targetLine.RTT)
			}
		}
	} else {
		log.Println("No active lines available!")
	}
}

func selectLineWeighted(lines []*ClientLine) *ClientLine {
	var totalScore float64
	var candidates []*ClientLine
	var scores []float64

	for _, line := range lines {
		line.Mu.Lock()
		alive := line.Alive
		rtt := line.RTT
		baseW := line.BaseWeight
		line.Mu.Unlock()

		if !alive {
			continue
		}

		ms := float64(rtt.Milliseconds())
		if ms <= 0 {
			ms = 1
		}

		score := float64(baseW) * (100.0 / ms)

		candidates = append(candidates, line)
		scores = append(scores, score)
		totalScore += score
	}

	if len(candidates) == 0 {
		return nil
	}

	r, _ := rand.Int(rand.Reader, big.NewInt(1000))
	randVal := float64(r.Int64()) / 1000.0 * totalScore

	current := 0.0
	for i, s := range scores {
		current += s
		if randVal < current {
			return candidates[i]
		}
	}
	return candidates[len(candidates)-1]
}

// --- 共通ユーティリティ ---

func performClientHandshake(conn net.Conn) error {
	challenge := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}
	hashed := sha256.Sum256(challenge)
	signature, err := rsa.SignPKCS1v15(rand.Reader, clientPrivKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}
	pubASN1, _ := x509.MarshalPKIXPublicKey(&clientPrivKey.PublicKey)
	pubBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1})
	msg := HandshakeMsg{PublicKey: pubBytes, Signature: signature}
	return gob.NewEncoder(conn).Encode(msg)
}

func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}