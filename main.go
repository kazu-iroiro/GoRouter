package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
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
	ProtocolVersion   = "BOND/4.2-DEBUG-FIX"
	ChallengeSize     = 32
	KeepAliveInterval = 10 * time.Second
	TunReadSize       = 4096 // バッファサイズを拡大
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
	Payload   []byte 
	IsFin     bool   
	Timestamp int64
}

// --- グローバル変数 ---
var (
	myPrivKey    *rsa.PrivateKey 
	targetPubKey *rsa.PublicKey  

	globalSeqID    int64      
	seqMu          sync.Mutex 
	
	debugMode      bool // デバッグフラグ
)

func main() {
	mode := flag.String("mode", "server", "Mode: server, client, or keygen")
	addr := flag.String("addr", "0.0.0.0:8080", "Server listen/connect address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	mtu := flag.Int("mtu", 1300, "Virtual Interface MTU")
	fragSize := flag.Int("frag", 1200, "Fragmentation size (Must be < MTU)")
	vip := flag.String("vip", "10.0.0.1/24", "Virtual IP CIDR for TUN interface")
	weights := flag.String("weights", "", "Comma separated weights")
	ifaces := flag.String("ifaces", "", "Comma separated interface names to bind")
	
	privKeyFile := flag.String("priv", "private.pem", "Private key file path (Client mode)")
	pubKeyFile := flag.String("pub", "public.pem", "Public key file path (Server mode)")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")

	flag.Parse()
	debugMode = *debug

	// --- モード分岐 ---

	if *mode == "keygen" {
		if err := generateAndSaveKeys(); err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		return
	}

	if *mode == "client" {
		var err error
		myPrivKey, err = loadPrivateKey(*privKeyFile)
		if err != nil {
			log.Fatalf("Failed to load private key from %s: %v", *privKeyFile, err)
		}
	} else if *mode == "server" {
		var err error
		targetPubKey, err = loadPublicKey(*pubKeyFile)
		if err != nil {
			log.Fatalf("Failed to load public key from %s: %v", *pubKeyFile, err)
		}
	}

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
// ログ出力用ヘルパー
// ==========================================
func debugLog(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// ==========================================
// 鍵管理・認証ロジック
// ==========================================

func generateAndSaveKeys() error {
	log.Println("Generating 2048-bit RSA key pair...")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return err }

	privFile, err := os.Create("private.pem")
	if err != nil { return err }
	defer privFile.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	log.Println("Saved: private.pem")

	pubFile, err := os.Create("public.pem")
	if err != nil { return err }
	defer pubFile.Close()
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pem.Encode(pubFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1})
	log.Println("Saved: public.pem")
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	block, _ := pem.Decode(data)
	if block == nil { return nil, fmt.Errorf("failed to parse PEM") }
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	block, _ := pem.Decode(data)
	if block == nil { return nil, fmt.Errorf("failed to parse PEM") }
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil { return nil, err }
	return pub.(*rsa.PublicKey), nil
}

// ==========================================
// TUN Interface Setup
// ==========================================

func setupTUN(cidr string, mtu int) (*water.Interface, error) {
	if runtime.GOOS != "linux" {
		log.Printf("[WARNING] You are running on %s. 'ip' commands may fail.", runtime.GOOS)
	}

	config := water.Config{ DeviceType: water.TUN }
	
	log.Println("Creating TUN device...")
	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN: %v", err)
	}
	log.Printf("TUN device created: Name=%s", iface.Name())

	time.Sleep(100 * time.Millisecond)

	log.Printf("Configuring IP %s and MTU %d...", cidr, mtu)
	// IP設定
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", iface.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip addr failed: %v, out: %s", err, out)
	}
	// リンクアップ & MTU
	cmd = exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprintf("%d", mtu), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link failed: %v, out: %s", err, out)
	}

	return iface, nil
}

// ==========================================
// パケット処理ロジック
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

// TUN -> Network
func tunToNetworkLoop(iface *water.Interface, conns []*ConnectionWrapper, fragSize int) {
	packet := make([]byte, TunReadSize)
	log.Println("Started TUN Reader Loop")

	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatalf("TUN read error: %v", err)
		}
		debugLog("TUN Read: %d bytes", n)

		rawData := packet[:n]
		offset := 0
		
		// SeqIDの発行（IPパケット単位ではなく、フラグメント単位で一意にする）
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

			if err := sendPacketWeighted(conns, pkt); err != nil {
				debugLog("Failed to send packet Seq:%d: %v", currentSeq, err)
			} else {
				// debugLog("Sent Seq:%d Size:%d Fin:%v", currentSeq, len(chunk), isLast)
			}
			offset = end
		}
	}
}

// Network -> TUN
func networkToTunLoop(iface *water.Interface, pktChan <-chan Packet) {
	var nextSeqID int64 = 0
	buffer := make(map[int64]Packet)
	var ipPacketBuffer bytes.Buffer
	
	log.Println("Started Network Reassembler Loop")

	processPacket := func(pkt Packet) {
		if pkt.Type != TypeData { return }

		ipPacketBuffer.Write(pkt.Payload)

		if pkt.IsFin {
			data := ipPacketBuffer.Bytes()
			n, err := iface.Write(data)
			if err != nil {
				log.Printf("TUN write error: %v", err)
			} else {
				debugLog("TUN Write: %d bytes (Original Seq:%d)", n, pkt.SeqID)
			}
			ipPacketBuffer.Reset()
		}
	}

	for pkt := range pktChan {
		// リセット検出: SeqID=0 が飛んできたら強制リセット
		if pkt.SeqID == 0 {
			log.Println("[INFO] SeqID Reset detected (Seq=0). Clearing buffers.")
			nextSeqID = 0
			buffer = make(map[int64]Packet)
			ipPacketBuffer.Reset()
		}

		if pkt.SeqID == nextSeqID {
			// 期待通りの順番
			processPacket(pkt)
			nextSeqID++

			// バッファ内の後続パケットを処理
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
			// 未来のパケット -> バッファへ
			debugLog("Buffered Seq:%d (Waiting for %d)", pkt.SeqID, nextSeqID)
			buffer[pkt.SeqID] = pkt
		} else {
			// 過去のパケット -> 無視
			debugLog("Dropped duplicate/old Seq:%d (Current: %d)", pkt.SeqID, nextSeqID)
		}
	}
}

// ==========================================
// サーバー側
// ==========================================

func runServer(iface *water.Interface, addr string, fragSize int) {
	listener, err := net.Listen("tcp", addr)
	if err != nil { log.Fatalf("Listen error: %v", err) }
	log.Printf("[Server] Listening on %s", addr)

	packetIngress := make(chan Packet, 1000)
	var clients []*ConnectionWrapper
	var clientsMu sync.Mutex

	// ダウンロード方向: Network -> TUN
	go networkToTunLoop(iface, packetIngress)

	// アップロード方向: TUN -> Network (全クライアントへ)
	go func() {
		packet := make([]byte, TunReadSize)
		for {
			n, err := iface.Read(packet)
			if err != nil { log.Fatal(err) }
			debugLog("Server TUN Read: %d bytes", n)
			
			rawData := packet[:n]
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
		if err != nil { continue }

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
					// debugLog("Recv Seq:%d", pkt.SeqID)
					packetIngress <- pkt
				}
			}
		}(conn)
	}
}

func serverHandshake(conn net.Conn) error {
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	if _, err := conn.Write(challenge); err != nil { return err }

	var sigLen uint16
	if err := binary.Read(conn, binary.BigEndian, &sigLen); err != nil { return err }

	sig := make([]byte, sigLen)
	if _, err := io.ReadFull(conn, sig); err != nil { return err }

	hashed := sha256.Sum256(challenge)
	if err := rsa.VerifyPKCS1v15(targetPubKey, crypto.SHA256, hashed[:], sig); err != nil {
		return fmt.Errorf("verify failed: %v", err)
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
		if i < len(wParts) { fmt.Sscanf(wParts[i], "%d", &manualWeights[i]) }
	}

	bindIfaces := strings.Split(ifaceStr, ",")
	conns := make([]*ConnectionWrapper, numLines)
	packetIngress := make(chan Packet, 1000)

	for i := 0; i < numLines; i++ {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		if i < len(bindIfaces) && strings.TrimSpace(bindIfaces[i]) != "" {
			targetIface := strings.TrimSpace(bindIfaces[i])
			if localAddr, err := resolveInterfaceIP(targetIface); err == nil {
				dialer.LocalAddr = localAddr
				log.Printf("[Line %d] Bind: %s (%s)", i, targetIface, localAddr.String())
			} else {
				log.Fatalf("Bind error: %v", err)
			}
		}

		c, err := dialer.Dial("tcp", serverAddr)
		if err != nil { log.Fatalf("Dial failed: %v", err) }

		if err := clientHandshake(c); err != nil { log.Fatalf("Handshake failed: %v", err) }
		log.Printf("[Line %d] Connected.", i)

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
					w.Mu.Lock(); w.Alive = false; w.Mu.Unlock()
					return
				}
				if pkt.Type == TypePong {
					rtt := time.Since(time.Unix(0, pkt.Timestamp))
					w.Mu.Lock(); w.RTT = rtt; w.Alive = true; w.Mu.Unlock()
				} else {
					packetIngress <- pkt
				}
			}
		}(cw)

		go func(w *ConnectionWrapper) {
			for range time.Tick(KeepAliveInterval) {
				if !w.Alive { return }
				p := Packet{Type: TypePing, Timestamp: time.Now().UnixNano()}
				w.Mu.Lock(); w.Enc.Encode(p); w.Mu.Unlock()
			}
		}(cw)
	}

	go networkToTunLoop(iface, packetIngress)
	tunToNetworkLoop(iface, conns, fragSize)
}

func clientHandshake(conn net.Conn) error {
	buf := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, buf); err != nil { return err }
	hashed := sha256.Sum256(buf)
	sig, err := rsa.SignPKCS1v15(rand.Reader, myPrivKey, crypto.SHA256, hashed[:])
	if err != nil { return err }
	if err := binary.Write(conn, binary.BigEndian, uint16(len(sig))); err != nil { return err }
	_, err = conn.Write(sig)
	return err
}

func resolveInterfaceIP(ifaceName string) (*net.TCPAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil { return nil, err }
	addrs, err := iface.Addrs()
	if err != nil { return nil, err }
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return &net.TCPAddr{IP: ip4, Port: 0}, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 found for %s", ifaceName)
}

func sendPacketWeighted(conns []*ConnectionWrapper, pkt Packet) error {
	type Candidate struct { C *ConnectionWrapper; Score float64 }
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

	if len(candidates) == 0 { return fmt.Errorf("no active lines") }

	r, _ := rand.Int(rand.Reader, big.NewInt(1000))
	randVal := float64(r.Int64()) / 1000.0 * totalScore
	
	var target *ConnectionWrapper
	current := 0.0
	for _, cand := range candidates {
		current += cand.Score
		if randVal < current { target = cand.C; break }
	}
	if target == nil { target = candidates[len(candidates)-1].C }

	target.Mu.Lock()
	err := target.Enc.Encode(pkt)
	target.Mu.Unlock()
	return err
}