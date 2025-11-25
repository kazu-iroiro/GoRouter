package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary" // 追加
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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
)

// --- 設定・定数 ---

const (
	ProtocolVersion   = "BOND/4.1-RAW-AUTH"
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

// HandshakeMsg 構造体は廃止し、直接バイナリ送信を行います

// --- グローバル変数 ---
var (
	// ファイルから読み込んだ鍵
	myPrivKey    *rsa.PrivateKey // クライアント用: 自分の秘密鍵
	targetPubKey *rsa.PublicKey  // サーバー用: 検証したいクライアントの公開鍵

	globalSeqID int64      // 送信用シーケンス番号
	seqMu       sync.Mutex // SeqID用Mutex
)

// initでの鍵自動生成は廃止

func main() {
	mode := flag.String("mode", "server", "Mode: server, client, or keygen")
	addr := flag.String("addr", "0.0.0.0:8080", "Server listen/connect address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	mtu := flag.Int("mtu", 1300, "Virtual Interface MTU")
	fragSize := flag.Int("frag", 1024, "Fragmentation size")
	vip := flag.String("vip", "10.0.0.1/24", "Virtual IP CIDR for TUN interface")
	weights := flag.String("weights", "", "Comma separated weights")
	ifaces := flag.String("ifaces", "", "Comma separated interface names to bind")

	// 鍵ファイル指定用フラグ
	privKeyFile := flag.String("priv", "private.pem", "Private key file path (Client mode)")
	pubKeyFile := flag.String("pub", "public.pem", "Public key file path (Server mode)")

	flag.Parse()

	// --- モード分岐 ---

	if *mode == "keygen" {
		if err := generateAndSaveKeys(); err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		return
	}

	// 鍵の読み込み
	if *mode == "client" {
		var err error
		myPrivKey, err = loadPrivateKey(*privKeyFile)
		if err != nil {
			log.Fatalf("Failed to load private key from %s: %v", *privKeyFile, err)
		}
		log.Printf("Loaded private key from %s", *privKeyFile)
	} else if *mode == "server" {
		var err error
		targetPubKey, err = loadPublicKey(*pubKeyFile)
		if err != nil {
			log.Fatalf("Failed to load public key from %s: %v", *pubKeyFile, err)
		}
		log.Printf("Loaded public key for verification from %s", *pubKeyFile)
	}

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

// ==========================================
// 鍵管理・認証ロジック
// ==========================================

// 鍵ペア生成と保存
func generateAndSaveKeys() error {
	log.Println("Generating 2048-bit RSA key pair...")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 秘密鍵の保存
	privFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer privFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}
	log.Println("Saved: private.pem")

	// 公開鍵の保存
	pubFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	if err := pem.Encode(pubFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1}); err != nil {
		return err
	}
	log.Println("Saved: public.pem")

	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

// ==========================================
// TUN Interface Setup
// ==========================================

func setupTUN(cidr string, mtu int) (*water.Interface, error) {
	if runtime.GOOS != "linux" {
		log.Printf("[WARNING] You are running on %s, but this code uses Linux-specific 'ip' commands.", runtime.GOOS)
	}

	config := water.Config{
		DeviceType: water.TUN,
	}

	log.Println("Attempting to create TUN device...")
	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}
	log.Printf("TUN device created successfully: Name=%s", iface.Name())

	time.Sleep(100 * time.Millisecond)

	log.Printf("Assigning IP %s to %s...", cidr, iface.Name())
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", iface.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip addr add failed: %v\nOutput: %s", err, string(out))
	}

	log.Printf("Setting MTU %d and bringing up %s...", mtu, iface.Name())
	cmd = exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link set up failed: %v\nOutput: %s", err, string(out))
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
			log.Println("Detected Seq Reset.")
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
				log.Printf("[Auth Failed] %v. Hint: Ensure Client's 'private.pem' matches Server's 'public.pem'.", err)
				c.Close()
				return
			}
			log.Printf("[Auth Success] Client verified: %s", c.RemoteAddr())

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

// サーバー側ハンドシェイク: gobを使わずRawバイナリで署名を検証
func serverHandshake(conn net.Conn) error {
	// 1. チャレンジ送信 (32 bytes)
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	if _, err := conn.Write(challenge); err != nil {
		return err
	}

	// 2. 署名長受信 (uint16)
	var sigLen uint16
	if err := binary.Read(conn, binary.BigEndian, &sigLen); err != nil {
		return err
	}

	// 3. 署名本体受信
	sig := make([]byte, sigLen)
	if _, err := io.ReadFull(conn, sig); err != nil {
		return err
	}

	// 4. 署名検証
	hashed := sha256.Sum256(challenge)
	if err := rsa.VerifyPKCS1v15(targetPubKey, crypto.SHA256, hashed[:], sig); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

// ==========================================
// クライアント側
// ==========================================

func runClient(iface *water.Interface, serverAddr string, numLines int, fragSize int, weightStr string, ifaceStr string) {
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

	for i := 0; i < numLines; i++ {
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
		log.Printf("[Line %d] Authenticated successfully.", i)

		cw := &ConnectionWrapper{
			ID: i, Conn: c, Enc: gob.NewEncoder(c),
			Alive: true, BaseWeight: manualWeights[i], RTT: 100 * time.Millisecond,
		}
		conns[i] = cw

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

func resolveInterfaceIP(ifaceName string) (*net.TCPAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return &net.TCPAddr{IP: ip4, Port: 0}, nil
			}
		}
	}
	return nil, fmt.Errorf("no valid IPv4 address found for interface %s", ifaceName)
}

// クライアント側ハンドシェイク: gobを使わずRawバイナリで署名を送信
func clientHandshake(conn net.Conn) error {
	// 1. チャレンジ受信
	buf := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	// 2. 署名作成
	hashed := sha256.Sum256(buf)
	sig, err := rsa.SignPKCS1v15(rand.Reader, myPrivKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// 3. 署名長送信 (uint16)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(sig))); err != nil {
		return err
	}

	// 4. 署名本体送信
	if _, err := conn.Write(sig); err != nil {
		return err
	}

	return nil
}

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