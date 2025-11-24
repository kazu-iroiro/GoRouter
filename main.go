package main

import (
	"bufio"
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
	"net"
	"os"
)

// --- 設定・定数 ---

const (
	ProtocolVersion = "BOND/1.0"
	ChallengeSize   = 32
)

// Packet はネットワークを流れるデータの単位です
type Packet struct {
	SeqID   int64  // 再構成用のシーケンス番号
	Payload []byte // データ本体
}

// HandshakeMsg は接続確立時の認証用メッセージです
type HandshakeMsg struct {
	PublicKey []byte // PEM形式の公開鍵
	Signature []byte // チャレンジに対する署名
}

// --- グローバル変数（簡易的な鍵管理） ---
// 実際の運用ではファイルから読み込みますが、サンプル動作のためにオンメモリで生成・保持します
var (
	serverPrivKey *rsa.PrivateKey
	clientPrivKey *rsa.PrivateKey
)

func init() {
	// デモ用に起動時に鍵を生成
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

// --- メイン処理 ---

func main() {
	mode := flag.String("mode", "server", "Mode: server or client")
	addr := flag.String("addr", "localhost:8080", "Server address")
	lines := flag.Int("lines", 2, "Number of connection lines (Client mode only)")
	flag.Parse()

	if *mode == "server" {
		runServer(*addr)
	} else {
		runClient(*addr, *lines)
	}
}

// --- サーバー側実装（再構成・集約） ---

func runServer(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server listen error: %v", err)
	}
	log.Printf("[Server] Listening on %s. Waiting for connections...", addr)

	// 受信したパケットを集約するチャネル
	packetStream := make(chan Packet, 100)

	// 集約・再構成ルーチン（インターネット側への送信を模倣）
	go aggregator(packetStream)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, packetStream)
	}
}

// handleConnection は各回線からの接続を処理し、認証後にパケットを読み込みます
func handleConnection(conn net.Conn, out chan<- Packet) {
	defer conn.Close()
	log.Printf("[Server] New connection from %s", conn.RemoteAddr())

	// 1. 認証フェーズ (簡易実装)
	// サーバーからチャレンジ(ランダムバイト)を送信
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	// クライアントからの署名を受信
	dec := gob.NewDecoder(conn)
	var authMsg HandshakeMsg
	if err := dec.Decode(&authMsg); err != nil {
		log.Printf("Auth read failed: %v", err)
		return
	}

	// 署名検証
	pubKey, err := parsePublicKey(authMsg.PublicKey)
	if err != nil {
		log.Printf("Invalid public key format")
		return
	}
	
	// SHA256ハッシュを作成して検証
	hashed := sha256.Sum256(challenge)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], authMsg.Signature)
	if err != nil {
		log.Printf("[Server] Authentication FAILED from %s", conn.RemoteAddr())
		return
	}
	log.Printf("[Server] Authentication SUCCESS from %s", conn.RemoteAddr())

	// 2. データ受信ループ
	for {
		var pkt Packet
		if err := dec.Decode(&pkt); err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}
		// 集約チャネルへ送信
		out <- pkt
	}
}

// aggregator は複数の回線から来たパケットを1系統にまとめ、本来は順序制御を行います
func aggregator(in <-chan Packet) {
	log.Println("[Server] Aggregator started. Reassembling packets...")
	
	// 本来はここでバッファリングを行い、SeqID順に並べ替える処理が必要です (Min-Heap等を使用)
	// 今回は簡易的に受信順に出力します
	
	for pkt := range in {
		// インターネット側への送信をシミュレーション（標準出力）
		fmt.Printf("[Internet-Out] Seq:%d | Data Size:%d bytes | Payload: %s\n", 
			pkt.SeqID, len(pkt.Payload), string(pkt.Payload))
	}
}

// --- クライアント側実装（振り分け） ---

func runClient(serverAddr string, numLines int) {
	log.Printf("[Client] Starting... Connecting to %s with %d lines", serverAddr, numLines)

	var conns []net.Conn
	var encoders []*gob.Encoder
	
	// 複数回線の確立
	for i := 0; i < numLines; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Fatalf("Dial failed for line %d: %v", i, err)
		}
		
		// 認証実行
		if err := performClientHandshake(conn); err != nil {
			log.Fatalf("Handshake failed for line %d: %v", i, err)
		}
		
		conns = append(conns, conn)
		encoders = append(encoders, gob.NewEncoder(conn))
		log.Printf("[Client] Line %d connected and authenticated", i)
	}

	defer func() {
		for _, c := range conns { c.Close() }
	}()

	// 下流（ユーザー側）からの入力をシミュレーション
	// 実際は TUN/TAP デバイスからの Read になります
	inputScanner := bufio.NewScanner(os.Stdin)
	log.Println("[Client] Ready. Type text and press Enter to send packets (split across lines).")

	var seqID int64 = 0
	
	// ラウンドロビン方式で振り分け
	currentLine := 0

	for inputScanner.Scan() {
		data := inputScanner.Bytes()
		
		// パケット作成
		pkt := Packet{
			SeqID:   seqID,
			Payload: data, // 本来はコピーが必要ですがデモのためそのまま
		}
		seqID++

		// 振り分けロジック (Round-Robin)
		targetEnc := encoders[currentLine]
		log.Printf("[Client] Sending Seq:%d via Line %d", pkt.SeqID, currentLine)

		if err := targetEnc.Encode(pkt); err != nil {
			log.Printf("Send error on line %d: %v", currentLine, err)
			// 本来はここで再接続や別の回線へのフォールバック処理が必要
		}

		currentLine = (currentLine + 1) % len(conns)
	}
}

func performClientHandshake(conn net.Conn) error {
	// 1. チャレンジ受信
	challenge := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}

	// 2. 署名作成
	hashed := sha256.Sum256(challenge)
	signature, err := rsa.SignPKCS1v15(rand.Reader, clientPrivKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// 公開鍵をバイト列化 (送信するため)
	pubASN1, _ := x509.MarshalPKIXPublicKey(&clientPrivKey.PublicKey)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 3. 認証メッセージ送信
	msg := HandshakeMsg{
		PublicKey: pubBytes,
		Signature: signature,
	}
	
	enc := gob.NewEncoder(conn)
	return enc.Encode(msg)
}

// --- ユーティリティ ---

func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}