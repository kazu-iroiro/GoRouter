// config.go
package main

import (
	"crypto/rsa"
	"encoding/gob"
	"math"
	"net"
	"sync"
	"time"
)

const (
	ProtocolVersion   = "BOND/4.14-AUTO-LINES"
	ChallengeSize     = 32
	KeepAliveInterval = 10 * time.Second
	TunReadSize       = 4096
	StallTimeout      = 1 * time.Second
	MaxSeqID          = math.MaxInt64
)

type PacketType int

const (
	TypeData PacketType = iota
	TypePing
	TypePong
)

type Packet struct {
	Type      PacketType
	SeqID     int64
	Payload   []byte
	IsFin     bool
	Timestamp int64
}

// ConnectionWrapper は他ファイルでも参照されるためここに配置
type ConnectionWrapper struct {
	ID         int
	Conn       net.Conn
	Enc        *gob.Encoder
	Mu         sync.Mutex
	Alive      bool
	RTT        time.Duration
	BaseWeight int
}

var (
	myPrivKey    *rsa.PrivateKey
	targetPubKey *rsa.PublicKey
	globalSeqID  int64
	seqMu        sync.Mutex
	debugMode    bool
)