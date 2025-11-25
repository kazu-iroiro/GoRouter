package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
)

// --- 設定・定数 ---

const (
	ProtocolVersion   = "BOND/3.4-CROSS-COMPAT"
	ChallengeSize     = 32
	KeepAliveInterval = 10 * time.Second
	TunReadSize       = 2000 // OSから読み取るパケットの最大サイズ
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
	IsFin     bool   // フラグメンテーションの終了コード
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
	globalSeqID   int64      // 送信用シーケンス番号
	seqMu         sync.Mutex // SeqID用Mutex
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
	addr := flag.String("addr", "0.0.0.0:8080", "Server listen/connect address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	mtu := flag.Int("mtu", 1300, "Virtual Interface MTU")
	fragSize := flag.Int("frag", 1024, "Fragmentation size")
	vip := flag.String("vip", "10.0.0.1/24", "Virtual IP CIDR for TUN interface")
	weights := flag.String("weights", "", "Comma separated weights")
	ifaces := flag.String("ifaces", "", "Comma separated interface names to bind (e.g. 'eth0,wlan0')")
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
		runClient(iface, *addr, *lines, *fragSize, *weights, *ifaces)
	}
}

// --- TUN Interface Setup ---

func setupTUN(cidr string, mtu int) (*water.Interface, error) {
	if runtime.GOOS != "linux" {
		log.Printf("[WARNING] You are running on %s, but this code uses Linux-specific 'ip' commands. It will likely fail.", runtime.GOOS)
	}

	// インターフェース設定
	config := water.Config{
		DeviceType: water.TUN,
	}
	// Note: config.PlatformSpecificParams.Name はLinux限定フィールドのため削除しました。
	// 名前はOSによって自動割り当てされます (例: tun0, tun1)

	// 1. TUNデバイスの作成
	log.Println("Attempting to create TUN device...")
	iface, err := water.New(config)
	if err != nil {
		// ここで詳細なエラーを返す
		return nil, fmt.Errorf("failed to create TUN device via syscall: %v\n(Hint: Are you running with sudo? Is /dev/net/tun accessible?)", err)
	}
	log.Printf("TUN device created successfully: Name=%s", iface.Name())

	// 2. リンクアップ待機 (OS認識待ち)
	time.Sleep(100 * time.Millisecond)

	// 3. IPアドレスの設定
	log.Printf("Assigning IP %s to %s...", cidr, iface.Name())
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", iface.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		// IP割り当て失敗
		return nil, fmt.Errorf("ip addr add failed: %v\nCommand Output: %s", err, string(out))
	}

	// 4. MTU設定とリンクアップ
	log.Printf("Setting MTU %d and bringing up %s...", mtu, iface.Name())
	cmd = exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		// リンクアップ失敗
		return nil, fmt.Errorf("ip link set up failed: %v\nCommand Output: %s", err, string(out))
	}

	return iface, nil
}

// ==========================================
// 共通ロジック (Reader/Writer)
// ==========================================

type ConnectionWrapper struct {
	ID         int
	Conn       net.Conn
	Enc        *gob.Encoder
	Mu         sync.Mutex
	Alive      bool
	RTT        time.Duration
	BaseWeight int
}

// TUNからパケットを読み出し -> 分割 -> ネットワークへ送信
func tunToNetworkLoop(iface *water.Interface, conns []*ConnectionWrapper, fragSize int) {
	packet := make([]byte, TunReadSize)

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
			currentSeq := globalSeqID
			globalSeqID++
			seqMu.Unlock()

			pkt := Packet{
				Type:    TypeData,
				SeqID:   currentSeq,
				Payload: chunk,
				IsFin:   isLast,
			}

			sendPacketWeighted(conns, pkt)
			offset = end
		}
	}
}

// ネットワークからパケット受信 -> 再構成 -> TUNへ書き込み
func networkToTunLoop(iface *water.Interface, pktChan <-chan Packet) {
	var nextSeqID int64 = 0
	buffer := make(map[int64]Packet)
	var ipPacketBuffer bytes.Buffer

	processPacket := func(pkt Packet) {
		if pkt.Type != TypeData {
			return
		}

		ipPacketBuffer.Write(pkt.Payload)

		if pkt.IsFin {
			data := ipPacketBuffer.Bytes()
			_, err := iface.Write(data)
			if err != nil {
				log.Printf("TUN write error: %v", err)
			}
			ipPacketBuffer.Reset()
		}
	}

	for pkt := range pktChan {
		if pkt.SeqID == 0 && nextSeqID != 0 {
			log.Println("Detected Seq Reset. Resetting reassembly buffer.")
			nextSeqID = 0
			buffer = make(map[int64]Packet)
			ipPacketBuffer.Reset()
		}

		if pkt.SeqID == nextSeqID {
			processPacket(pkt)
			nextSeqID++

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
			buffer[pkt.SeqID] = pkt
		}
	}
}

// ==========================================
// サーバー側
// ==========================================

func runServer(iface *water.Interface, addr string, fragSize int) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	log.Printf("[Server] Listening on %s", addr)

	packetIngress := make(chan Packet, 1000)
	var clients []*ConnectionWrapper
	var clientsMu sync.Mutex

	// [Download方向] Network -> TUN -> Internet
	go networkToTunLoop(iface, packetIngress)

	// [Upload方向] Internet -> TUN -> Network (全クライアントへ)
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

				pkt := Packet{
					Type:    TypeData,
					SeqID:   currentSeq,
					Payload: chunk,
					IsFin:   isLast,
				}

				clientsMu.Lock()
				sendPacketWeighted(clients, pkt)
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
				c.Close()
				return
			}

			wrapper := &ConnectionWrapper{
				Conn: c, Enc: gob.NewEncoder(c), Alive: true, BaseWeight: 10, RTT: 10 * time.Millisecond,
			}

			clientsMu.Lock()
			wrapper.ID = len(clients)
			clients = append(clients, wrapper)
			clientsMu.Unlock()

			log.Printf("Client connected: %s", c.RemoteAddr())

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
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	conn.Write(challenge)
	var msg HandshakeMsg
	if err := gob.NewDecoder(conn).Decode(&msg); err != nil {
		return err
	}
	return nil
}

// ==========================================
// クライアント側
// ==========================================

func runClient(iface *water.Interface, serverAddr string, numLines int, fragSize int, weightStr string, ifaceStr string) {
	// 重み設定
	manualWeights := make([]int, numLines)
	wParts := strings.Split(weightStr, ",")
	for i := 0; i < numLines; i++ {
		manualWeights[i] = 10
		if i < len(wParts) {
			fmt.Sscanf(wParts[i], "%d", &manualWeights[i])
		}
	}

	// インターフェース設定
	bindIfaces := strings.Split(ifaceStr, ",")

	conns := make([]*ConnectionWrapper, numLines)
	packetIngress := make(chan Packet, 1000)

	for i := 0; i < numLines; i++ {
		// 特定のインターフェースにバインドするDialerを作成
		dialer := net.Dialer{Timeout: 10 * time.Second}

		if i < len(bindIfaces) && strings.TrimSpace(bindIfaces[i]) != "" {
			targetIface := strings.TrimSpace(bindIfaces[i])
			localAddr, err := resolveInterfaceIP(targetIface)
			if err != nil {
				log.Fatalf("Failed to resolve interface %s for line %d: %v", targetIface, i, err)
			}
			dialer.LocalAddr = localAddr
			log.Printf("[Line %d] Binding to interface %s (%s)", i, targetIface, localAddr.String())
		}

		c, err := dialer.Dial("tcp", serverAddr)
		if err != nil {
			log.Fatalf("Dial failed line %d: %v", i, err)
		}

		if err := clientHandshake(c); err != nil {
			log.Fatalf("Handshake failed: %v", err)
		}

		cw := &ConnectionWrapper{
			ID: i, Conn: c, Enc: gob.NewEncoder(c),
			Alive: true, BaseWeight: manualWeights[i], RTT: 100 * time.Millisecond,
		}
		conns[i] = cw

		// 受信ループ
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
				if !wrapper.Alive {
					return
				}
				p := Packet{Type: TypePing, Timestamp: time.Now().UnixNano()}
				wrapper.Mu.Lock()
				wrapper.Enc.Encode(p)
				wrapper.Mu.Unlock()
			}
		}(cw)
	}

	log.Println("[Client] VPN Tunnel Established.")

	go networkToTunLoop(iface, packetIngress)
	tunToNetworkLoop(iface, conns, fragSize)
}

// resolveInterfaceIP はインターフェース名からTCPAddrを解決します
func resolveInterfaceIP(ifaceName string) (*net.TCPAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// IPv4アドレスを優先して探す
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return &net.TCPAddr{IP: ip4, Port: 0}, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid IPv4 address found for interface %s", ifaceName)
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
// ユーティリティ
// ==========================================

func sendPacketWeighted(conns []*ConnectionWrapper, pkt Packet) {
	type Candidate struct {
		C     *ConnectionWrapper
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
		return
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
	if err != nil {
		log.Printf("Send failed on line %d", target.ID)
	}
}