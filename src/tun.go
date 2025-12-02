package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/songgao/water"
)

func setupTUN(cidr string, mtu int) (*water.Interface, error) {
	if runtime.GOOS != "linux" {
		log.Printf("[WARNING] You are running on %s. 'ip' commands may fail.", runtime.GOOS)
	}

	config := water.Config{DeviceType: water.TUN}

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