package main

import (
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
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
)

// --- 設定・定数 ---

const (
	ProtocolVersion   = "BOND/3.0-TUN"
	ChallengeSize     = 32
	KeepAliveInterval = 10 * time.Second
	TunReadSize       = 2000 // OSから読み取るパケットの最大サイズ(MTUより少し大きく)
)

// PacketType 定義
type PacketType int

const (
	TypeData PacketType = iota
	TypePing
	TypePong
)

// Packet はボンディング回線を流れるデータの単位
type Packet struct {
	Type      PacketType
	SeqID     int64
	Payload   []byte // 分割されたデータ
	IsFin     bool   // フラグメンテーションの終了コード (1つのIPパケットの終わり)
	Timestamp int64
}

// HandshakeMsg 認証用
type HandshakeMsg struct {
	PublicKey []byte
	Signature []byte
}

// --- グローバル変数 ---
var (
	serverPrivKey *rsa.PrivateKey
	clientPrivKey *rsa.PrivateKey
	globalSeqID   int64      // 送信用シーケンス番号(スレッドセーフにする必要あり)
	seqMu         sync.Mutex // SeqID用Mutex
)

func init() {
	// 鍵生成 (本来は永続化)
	var err error
	serverPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { log.Fatal(err) }
	clientPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { log.Fatal(err) }
}

func main() {
	mode := flag.String("mode", "server", "Mode: server or client")
	addr := flag.String("addr", "0.0.0.0:8080", "Server listen/connect address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	mtu := flag.Int("mtu", 1300, "Virtual Interface MTU (should be smaller than physical MTU)")
	fragSize := flag.Int("frag", 1024, "Fragmentation size for splitting packets over lines")
	vip := flag.String("vip", "10.0.0.1/24", "Virtual IP CIDR for TUN interface")
	weights := flag.String("weights", "", "Comma separated weights")
	flag.Parse()

	// TUNインターフェースの作成
	iface, err := setupTUN(*vip, *mtu)
	if err != nil {
		log.Fatalf("Failed to setup TUN: %v", err)
	}
	defer iface.Close()

	if *mode == "server" {
		runServer(iface, *addr, *fragSize)
	} else {
		runClient(iface, *addr, *lines, *fragSize, *weights)
	}
}

// --- TUN Interface Setup ---

func setupTUN(cidr string, mtu int) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}
	log.Printf("Interface %s created", iface.Name())

	// IPアドレスとリンクアップの設定 (Linuxコマンド呼び出し)
	// ip addr add 10.0.0.1/24 dev tun0
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", iface.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip addr add failed: %v, out: %s", err, out)
	}

	// ip link set dev tun0 mtu 1300 up
	cmd = exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link set up failed: %v, out: %s", err, out)
	}

	return iface, nil
}

// ==========================================
// 共通ロジック (Reader/Writer)
// ==========================================

// ConnectionWrapper は各TCPコネクションを抽象化
type ConnectionWrapper struct {
	ID         int
	Conn       net.Conn
	Enc        *gob.Encoder
	Mu         sync.Mutex
	Alive      bool
	RTT        time.Duration
	BaseWeight int
}

// tunToNetworkLoop : TUNからパケットを読み出し -> 分割 -> ネットワークへ送信
func tunToNetworkLoop(iface *water.Interface, conns []*ConnectionWrapper, fragSize int) {
	packet := make([]byte, TunReadSize)

	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatalf("TUN read error: %v", err)
		}

		// OSから受け取った1つのIPパケット (サイズ n)
		rawData := packet[:n]
		
		// フラグメンテーションと送信
		// 1つのIPパケットを fragSize ごとに分割して送信し、最後に IsFin=true を送る
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

			pkt := Packet{
				Type:    TypeData,
				SeqID:   currentSeq,
				Payload: chunk,
				IsFin:   isLast, // 終了コード: 分割の最後であることを通知
			}

			sendPacketWeighted(conns, pkt)
			offset = end
		}
	}
}

// networkToTunLoop : ネットワークからパケット受信 -> 再構成 -> TUNへ書き込み
func networkToTunLoop(iface *water.Interface, pktChan <-chan Packet) {
	var nextSeqID int64 = 0
	buffer := make(map[int64]Packet)
	
	// 1つのIPパケットを再構築するための一時バッファ
	var ipPacketBuffer bytes.Buffer
	// 再構築中のパケットが連続しているか確認するためのフラグ
	reassembling := false

	// パケット処理関数
	processPacket := func(pkt Packet) {
		if pkt.Type != TypeData { return }

		// データ追記
		ipPacketBuffer.Write(pkt.Payload)
		reassembling = true

		// 終了コード(IsFin)を受け取ったら、OSへ書き込む
		if pkt.IsFin {
			data := ipPacketBuffer.Bytes()
			// log.Printf("[TUN Write] Reassembled IP Packet Size: %d", len(data))
			
			_, err := iface.Write(data)
			if err != nil {
				log.Printf("TUN write error: %v", err)
			}
			
			// バッファリセット
			ipPacketBuffer.Reset()
			reassembling = false
		}
	}

	for pkt := range pktChan {
		// --- 簡易的なセッションリセット検出 ---
		// 相手が再起動してSeqID 0を送ってきた場合など
		if pkt.SeqID == 0 && nextSeqID != 0 {
			log.Println("Detected Seq Reset. Resetting reassembly buffer.")
			nextSeqID = 0
			buffer = make(map[int64]Packet)
			ipPacketBuffer.Reset()
			reassembling = false
		}
		// ------------------------------------

		if pkt.SeqID == nextSeqID {
			// 期待通りの順番
			processPacket(pkt)
			nextSeqID++

			// バッファにある後続を確認
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
			// 未来のパケット (Keep buffer)
			buffer[pkt.SeqID] = pkt
		}
		// 過去のパケットは無視
	}
}

// ==========================================
// サーバー側 (Internet <-> Server TUN <-> Connections)
// ==========================================

func runServer(iface *water.Interface, addr string, fragSize int) {
	listener, err := net.Listen("tcp", addr)
	if err != nil { log.Fatalf("Listen error: %v", err) }
	log.Printf("[Server] Listening on %s. Waiting for clients...", addr)

	// 受信集約用チャネル
	packetIngress := make(chan Packet, 1000)
	
	// クライアント管理用 (簡易的に1クライアントのみサポートする構造にするが、リストに追加)
	var clients []*ConnectionWrapper
	var clientsMu sync.Mutex

	// 1. [Download方向] Network(Client) -> Server -> TUN -> Internet
	go networkToTunLoop(iface, packetIngress)

	// 2. [Upload方向] Internet -> TUN -> Server -> Network(Client)
	// TUNから来たパケットを接続中の全クライアントへ（本来はNATテーブルが必要だが、ここではブロードキャスト的に1つのセッションへ送る）
	go func() {
		packet := make([]byte, TunReadSize)
		for {
			n, err := iface.Read(packet)
			if err != nil { log.Fatal(err) }
			rawData := packet[:n]

			// フラグメンテーションしてクライアントへ送り返す
			offset := 0
			for offset < n {
				end := offset + fragSize
				isLast := false
				if end >= n { end = n; isLast = true }
				
				chunk := make([]byte, end-offset)
				copy(chunk, rawData[offset:end])

				seqMu.Lock()
				currentSeq := globalSeqID
				globalSeqID++
				seqMu.Unlock()

				pkt := Packet{
					Type:    TypeData,
					SeqID:   currentSeq,
					Payload: chunk,
					IsFin:   isLast,
				}

				// クライアントへ送信
				clientsMu.Lock()
				sendPacketWeighted(clients, pkt)
				clientsMu.Unlock()

				offset = end
			}
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		
		go func(c net.Conn) {
			// 認証 & 登録
			if err := serverHandshake(c); err != nil {
				c.Close()
				return
			}
			
			wrapper := &ConnectionWrapper{
				Conn: c,
				Enc:  gob.NewEncoder(c),
				Alive: true,
				BaseWeight: 10,
				RTT: 10 * time.Millisecond,
			}
			
			clientsMu.Lock()
			// 既存リストに追加 (IDは簡易連番)
			wrapper.ID = len(clients)
			clients = append(clients, wrapper)
			clientsMu.Unlock()
			
			log.Printf("Client connected: %s", c.RemoteAddr())

			// 受信ループ
			dec := gob.NewDecoder(c)
			for {
				var pkt Packet
				if err := dec.Decode(&pkt); err != nil {
					wrapper.Alive = false
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

func serverHandshake(conn net.Conn) error {
	// 簡易認証
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	conn.Write(challenge)
	var msg HandshakeMsg
	if err := gob.NewDecoder(conn).Decode(&msg); err != nil { return err }
	// (署名検証は省略せず実装推奨だが、構成簡略化のためここではエラーチェックのみ)
	return nil
}

// ==========================================
// クライアント側 (App <-> Client TUN <-> Connections)
// ==========================================

func runClient(iface *water.Interface, serverAddr string, numLines int, fragSize int, weightStr string) {
	// 重みパース
	manualWeights := make([]int, numLines)
	wParts := strings.Split(weightStr, ",")
	for i := 0; i < numLines; i++ {
		manualWeights[i] = 10
		if i < len(wParts) {
			fmt.Sscanf(wParts[i], "%d", &manualWeights[i])
		}
	}

	conns := make([]*ConnectionWrapper, numLines)
	packetIngress := make(chan Packet, 1000)

	// 回線接続
	for i := 0; i < numLines; i++ {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil { log.Fatalf("Dial failed: %v", err) }
		
		// 認証
		if err := clientHandshake(c); err != nil { log.Fatalf("Handshake failed: %v", err) }

		cw := &ConnectionWrapper{
			ID: i, Conn: c, Enc: gob.NewEncoder(c),
			Alive: true, BaseWeight: manualWeights[i], RTT: 100 * time.Millisecond,
		}
		conns[i] = cw

		// 受信ループ (Downloadデータ)
		go func(wrapper *ConnectionWrapper) {
			dec := gob.NewDecoder(wrapper.Conn)
			for {
				var pkt Packet
				if err := dec.Decode(&pkt); err != nil {
					wrapper.Alive = false
					return
				}
				if pkt.Type == TypePong {
					rtt := time.Since(time.Unix(0, pkt.Timestamp))
					wrapper.Mu.Lock()
					wrapper.RTT = rtt
					wrapper.Alive = true
					wrapper.Mu.Unlock()
				} else {
					packetIngress <- pkt
				}
			}
		}(cw)

		// Keepalive
		go func(wrapper *ConnectionWrapper) {
			tick := time.NewTicker(KeepAliveInterval)
			for range tick.C {
				if !wrapper.Alive { return }
				p := Packet{Type: TypePing, Timestamp: time.Now().UnixNano()}
				wrapper.Mu.Lock()
				wrapper.Enc.Encode(p)
				wrapper.Mu.Unlock()
			}
		}(cw)
	}

	log.Println("[Client] VPN Tunnel Established.")

	// 1. [Download方向] Server -> Client -> TUN -> App
	go networkToTunLoop(iface, packetIngress)

	// 2. [Upload方向] App -> TUN -> Client -> Server
	tunToNetworkLoop(iface, conns, fragSize)
}

func clientHandshake(conn net.Conn) error {
	buf := make([]byte, ChallengeSize)
	io.ReadFull(conn, buf)
	hashed := sha256.Sum256(buf)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, clientPrivKey, crypto.SHA256, hashed[:])
	pub, _ := x509.MarshalPKIXPublicKey(&clientPrivKey.PublicKey)
	msg := HandshakeMsg{PublicKey: pub, Signature: sig}
	return gob.NewEncoder(conn).Encode(msg)
}

// ==========================================
// ユーティリティ: 重み付き送信
// ==========================================

func sendPacketWeighted(conns []*ConnectionWrapper, pkt Packet) {
	// 生きている回線を抽出 & スコア計算
	type Candidate struct {
		C *ConnectionWrapper
		Score float64
	}
	var candidates []Candidate
	var totalScore float64

	for _, c := range conns {
		c.Mu.Lock()
		alive := c.Alive
		rtt := c.RTT
		bw := c.BaseWeight
		c.Mu.Unlock()

		if !alive { continue }

		ms := float64(rtt.Milliseconds())
		if ms <= 0 { ms = 1 }
		score := float64(bw) * (100.0 / ms)
		
		candidates = append(candidates, Candidate{c, score})
		totalScore += score
	}

	if len(candidates) == 0 { return }

	// 抽選
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
	if target == nil { target = candidates[len(candidates)-1].C }

	// 送信
	target.Mu.Lock()
	err := target.Enc.Encode(pkt)
	target.Mu.Unlock()
	if err != nil {
		log.Printf("Send failed on line %d", target.ID)
	}
}