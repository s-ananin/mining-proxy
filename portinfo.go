package main

import (
	"net"
	"sort"
	"strconv"

	"mining-proxy/iptables"
	"mining-proxy/proxy"
)

// portInfo — ответ /port-info: картина NAT по conntrack + пулы, до которых
// реально дошли соединения прокси (сверка «что перехвачено ↔ что работает»).
type portInfo struct {
	iptables.PortInfo
	ProxyPools []proxyPool `json:"proxy_pools"`
}

// proxyPool — пул с активными соединениями через прокси.
type proxyPool struct {
	Pool        string `json:"pool"`
	Port        int    `json:"port"`
	Connections int    `json:"connections"`
	Workers     int    `json:"workers"`
	Coin        string `json:"coin,omitempty"`
}

// proxyPools сводит пулы из статистики прокси (ключ пула — "ip:port").
func proxyPools(pools []proxy.PoolReport) []proxyPool {
	out := make([]proxyPool, 0, len(pools))
	for _, p := range pools {
		pp := proxyPool{Pool: p.Pool, Connections: p.Connections, Workers: p.Workers, Coin: p.Coin}
		if _, port, err := net.SplitHostPort(p.Pool); err == nil {
			pp.Port, _ = strconv.Atoi(port)
		}
		out = append(out, pp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Pool < out[j].Pool
	})
	return out
}
