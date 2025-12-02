package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
)

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
	log.Printf("Enabling NAT (Masquerade) on %s...", tunName)
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", tunName, "-j", "MASQUERADE")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to setup iptables NAT: %v, %s", err, out)
	}

	// 3. FORWARD チェーンの許可
	exec.Command("iptables", "-A", "FORWARD", "-o", tunName, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-i", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	return nil
}

func cleanupRouterMode(tunName string) {
	if runtime.GOOS != "linux" {
		return
	}
	log.Println("Disabling NAT and IP Forwarding...")

	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", tunName, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", tunName, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
}

func setupRoutes(tunName, serverIP string, gatewayIPs []string, bindIfaces []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic routing is only supported on Linux")
	}

	// 1. Policy Routing
	startTableID := 201

	for i, gw := range gatewayIPs {
		if i >= len(bindIfaces) || bindIfaces[i] == "" {
			continue
		}
		ifName := bindIfaces[i]
		tableID := fmt.Sprintf("%d", startTableID+i)

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
	if runtime.GOOS != "linux" {
		return
	}

	log.Println("Restoring routing table...")
	exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", tunName).Run()
	exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", tunName).Run()
	exec.Command("ip", "route", "del", serverIP).Run()

	startTableID := 201
	for i, _ := range gatewayIPs {
		if i >= len(bindIfaces) || bindIfaces[i] == "" {
			continue
		}
		ifName := bindIfaces[i]
		tableID := fmt.Sprintf("%d", startTableID+i)

		localAddr, err := resolveInterfaceIP(ifName)
		if err == nil {
			srcIP := localAddr.IP.String()
			exec.Command("ip", "rule", "del", "from", srcIP, "table", tableID).Run()
		}
		exec.Command("ip", "route", "del", serverIP, "table", tableID).Run()
		exec.Command("ip", "route", "flush", "table", tableID).Run()
	}
}