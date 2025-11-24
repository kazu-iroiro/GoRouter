# GoRouter

# How to run
```
go mod init bonding
go get github.com/songgao/water
```

#### 1. サーバー側 (IP: x.x.x.x, TUN IP: 10.0.0.1)
```bash
# パケット転送を許可
sudo sysctl -w net.ipv4.ip_forward=1

# プログラム起動
sudo ./bonding -mode server -vip 10.0.0.1/24 -addr :8080

# (別ターミナル) TUNからのトラフィックを物理NIC(eth0など)から出ていく際にNATする
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

#### 2. クライアント側 (TUN IP: 10.0.0.2)
```bash
# プログラム起動 (サーバーへ接続)
sudo ./bonding -mode client -vip 10.0.0.2/24 -addr x.x.x.x:8080 -lines 2

# (別ターミナル) 特定の通信をTUN経由にするテスト
ping 10.0.0.1
# またはデフォルトルートをTUNに向ける（全トラフィックをVPN経由にする場合）
sudo ip route add 0.0.0.0/1 dev tun0
```

old version
```
server side: go run main.go -mode server
client side: go run main.go -mode client -lines 2 -mtu 5 -weights "1,2"
```