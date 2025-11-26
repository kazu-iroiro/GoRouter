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
	"math"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
)

// --- 設定・定数 ---

const (
	ProtocolVersion   = "BOND/4.14-AUTO-LINES"
	ChallengeSize     = 32
	KeepAliveInterval = 10 * time.Second
	TunReadSize       = 4096 
	StallTimeout      = 1 * time.Second // パケット待ちのタイムアウト時間

	// SeqIDの上限
	// math.MaxInt64 = 9223372036854775807
	MaxSeqID          = math.MaxInt64 
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
	
	debugMode      bool
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

	// ルーティング自動設定用のフラグ
	redirectGw := flag.Bool("redirect-gateway", false, "Automatically redirect all traffic through the tunnel (Client only)")
	gatewayIP := flag.String("gw", "", "Physical gateway IPs comma separated (Required if -redirect-gateway is used)")
	routerMode := flag.Bool("router", false, "Enable IP forwarding and NAT to act as a gateway for LAN devices (Client only)")

	flag.Parse()
	debugMode = *debug

	// --- 接続数の自動調整ロジック ---
	if *mode == "client" && *ifaces != "" {
		// カンマ区切りでインターフェース数をカウント
		count := 0
		for _, iface := range strings.Split(*ifaces, ",") {
			if strings.TrimSpace(iface) != "" {
				count++
			}
		}
		// 指定されたインターフェース数が -lines より多い場合、自動的に増やす
		if count > *lines {
			log.Printf("[Config] Auto-adjusting connection lines: %d -> %d (matched to -ifaces)", *lines, count)
			*lines = count
		}
	}
	// -----------------------------

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
		// ルーティング・ルーター設定の適用（クライアントモードのみ）
		var cleanupFunc func() // クリーンアップ関数を保持
		
		// ルーターモード設定 (IP Forwarding + NAT)
		if *routerMode {
			if err := setupRouterMode(iface.Name()); err != nil {
				log.Printf("[WARN] Failed to setup router mode: %v", err)
			} else {
				log.Println("[INFO] Router mode enabled (IP Forwarding + NAT). This device can now act as a gateway.")
			}
		}

		if *redirectGw {
			if *gatewayIP == "" {
				log.Fatal("Error: -gw (physical gateway IP) is required when using -redirect-gateway. Use comma for multiple gateways.")
			}
			serverHost, _, err := net.SplitHostPort(*addr)
			if err != nil {
				serverHost = *addr
			}

			gateways := strings.Split(*gatewayIP, ",")
			bindIfacesList := strings.Split(*ifaces, ",")
			for i := range gateways { gateways[i] = strings.TrimSpace(gateways[i]) }
			for i := range bindIfacesList { bindIfacesList[i] = strings.TrimSpace(bindIfacesList[i]) }

			// クリーンアップ関数定義
			cleanupFunc = func() {
				log.Println("\n[INFO] Cleaning up routes and firewall rules...")
				cleanupRoutes(iface.Name(), serverHost, gateways, bindIfacesList)
				if *routerMode {
					cleanupRouterMode(iface.Name())
				}
				iface.Close()
			}

			// ルート設定適用
			if err := setupRoutes(iface.Name(), serverHost, gateways, bindIfacesList); err != nil {
				log.Printf("[WARN] Failed to setup routes: %v", err)
			} else {
				log.Println("[INFO] Routes configured. All traffic is redirected through tunnel.")
			}
			
			// シグナルハンドリング
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-c
				if cleanupFunc != nil { cleanupFunc() }
				os.Exit(0)
			}()
		}

		// クライアント実行
		runClient(iface, *addr, *lines, *fragSize, *weights, *ifaces, cleanupFunc)
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
// ルーターモード設定 (IP Forwarding & NAT)
// ==========================================

func setupRouterMode(tunName string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("router mode is only supported on Linux")
	}

	// 1. IP Forwarding 有効化
	log.Println("Enabling IP Forwarding...")
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %v, %s", err, out)
	}

	// 2. TUNインターフェースでのNAT (Masquerade) 設定
	// これにより、下流からのパケットがTUNのIPとして送信される
	log.Printf("Enabling NAT (Masquerade) on %s...", tunName)
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", tunName, "-j", "MASQUERADE")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to setup iptables NAT: %v, %s", err, out)
	}

	// 3. FORWARD チェーンの許可 (念のため)
	// 下流 -> TUN
	exec.Command("iptables", "-A", "FORWARD", "-o", tunName, "-j", "ACCEPT").Run()
	// TUN -> 下流 (確立済み接続)
	exec.Command("iptables", "-A", "FORWARD", "-i", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	return nil
}

func cleanupRouterMode(tunName string) {
	if runtime.GOOS != "linux" { return }
	log.Println("Disabling NAT and IP Forwarding...")
	
	// NAT削除
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", tunName, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", tunName, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	
	// IP Forwarding は他の影響を考慮して戻さないのが一般的だが、ここでは戻さないでおく
	// exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run()
}

// ==========================================
// ルーティング設定 (Linux Policy Routing)
// ==========================================

func setupRoutes(tunName, serverIP string, gatewayIPs []string, bindIfaces []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic routing is only supported on Linux")
	}

	// 1. Policy Routing
	startTableID := 201

	for i, gw := range gatewayIPs {
		if i >= len(bindIfaces) || bindIfaces[i] == "" { continue }
		ifName := bindIfaces[i]
		tableID := fmt.Sprintf("%d", startTableID + i)

		localAddr, err := resolveInterfaceIP(ifName)
		if err != nil {
			return fmt.Errorf("failed to resolve IP for %s: %v", ifName, err)
		}
		srcIP := localAddr.IP.String()

		if srcIP == gw {
			return fmt.Errorf("invalid configuration: Gateway IP (%s) matches Interface IP (%s).", gw, srcIP)
		}

		log.Printf("Setting up policy routing for %s (IP: %s, GW: %s, Table: %s)", ifName, srcIP, gw, tableID)

		exec.Command("ip", "rule", "del", "from", srcIP, "table", tableID).Run()
		cmd := exec.Command("ip", "rule", "add", "from", srcIP, "table", tableID, "prio", "100")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rule add failed: %v, %s", err, out)
		}

		exec.Command("ip", "route", "del", serverIP, "table", tableID).Run()
		cmd = exec.Command("ip", "route", "add", serverIP, "via", gw, "dev", ifName, "table", tableID, "onlink")
		if out, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("route add table failed: %v, %s", err, out)
			}
		}
	}

	// 2. メインテーブルへのフォールバックルート追加
	if len(gatewayIPs) > 0 && len(bindIfaces) > 0 {
		fallbackGW := gatewayIPs[0]
		log.Printf("Adding fallback route to VPN Server %s via %s (Main Table)", serverIP, fallbackGW)
		
		exec.Command("ip", "route", "del", serverIP).Run()
		cmd := exec.Command("ip", "route", "add", serverIP, "via", fallbackGW)
		if out, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") {
				log.Printf("[WARN] Failed to add fallback route to main table: %v", err)
			}
		}
	}

	// 3. デフォルトルートをTUNに向ける
	log.Printf("Redirecting all traffic to %s (Main Table)", tunName)
	
	exec.Command("ip", "route", "del", "0.0.0.0/1").Run()
	if out, err := exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", tunName).CombinedOutput(); err != nil {
		cleanupRoutes(tunName, serverIP, gatewayIPs, bindIfaces)
		return fmt.Errorf("failed to add 0.0.0.0/1: %v, %s", err, out)
	}

	exec.Command("ip", "route", "del", "128.0.0.0/1").Run()
	if out, err := exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", tunName).CombinedOutput(); err != nil {
		cleanupRoutes(tunName, serverIP, gatewayIPs, bindIfaces)
		return fmt.Errorf("failed to add 128.0.0.0/1: %v, %s", err, out)
	}

	return nil
}

func cleanupRoutes(tunName, serverIP string, gatewayIPs []string, bindIfaces []string) {
	if runtime.GOOS != "linux" { return }

	log.Println("Restoring routing table...")
	exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", tunName).Run()
	exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", tunName).Run()
	exec.Command("ip", "route", "del", serverIP).Run()

	startTableID := 201
	for i, _ := range gatewayIPs {
		if i >= len(bindIfaces) || bindIfaces[i] == "" { continue }
		ifName := bindIfaces[i]
		tableID := fmt.Sprintf("%d", startTableID + i)
		
		localAddr, err := resolveInterfaceIP(ifName)
		if err == nil {
			srcIP := localAddr.IP.String()
			exec.Command("ip", "rule", "del", "from", srcIP, "table", tableID).Run()
		}
		exec.Command("ip", "route", "del", serverIP, "table", tableID).Run()
		exec.Command("ip", "route", "flush", "table", tableID).Run()
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
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", iface.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip addr failed: %v, out: %s", err, out)
	}
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
		if pkt.Type != TypeData { return }
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
				for k := range buffer { keys = append(keys, k) }
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

	go networkToTunLoop(iface, packetIngress)

	go func() {
		packet := make([]byte, TunReadSize)
		for {
			n, err := iface.Read(packet)
			if err != nil { log.Fatal(err) }
			
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
					wrapper.Mu.Lock(); wrapper.Alive = false; wrapper.Mu.Unlock()
					return
				}
				if pkt.Type == TypePing {
					go func(p Packet) {
						pong := Packet{Type: TypePong, Timestamp: p.Timestamp}
						wrapper.Mu.Lock(); wrapper.Enc.Encode(pong); wrapper.Mu.Unlock()
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

// cleanupFunc引数を追加
func runClient(iface *water.Interface, serverAddr string, numLines int, fragSize int, weightStr string, ifaceStr string, cleanupFunc func()) {
	manualWeights := make([]int, numLines)
	wParts := strings.Split(weightStr, ",")
	for i := 0; i < numLines; i++ {
		manualWeights[i] = 10
		if i < len(wParts) { fmt.Sscanf(wParts[i], "%d", &manualWeights[i]) }
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

	// 全回線失敗なら終了
	if successCount == 0 {
		log.Println("All connections failed. Exiting.")
		if cleanupFunc != nil { cleanupFunc() }
		os.Exit(1)
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
		if c == nil { continue } // 接続失敗したLineはnilの可能性あり
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

	if err == nil {
		debugLog("Sent Seq:%d Size:%d via Line %d", pkt.SeqID, len(pkt.Payload), target.ID)
	}

	return err
}