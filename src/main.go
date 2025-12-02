package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
			for i := range gateways {
				gateways[i] = strings.TrimSpace(gateways[i])
			}
			for i := range bindIfacesList {
				bindIfacesList[i] = strings.TrimSpace(bindIfacesList[i])
			}

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
				if cleanupFunc != nil {
					cleanupFunc()
				}
				os.Exit(0)
			}()
		}

		// クライアント実行
		runClient(iface, *addr, *lines, *fragSize, *weights, *ifaces, cleanupFunc)
	}
}