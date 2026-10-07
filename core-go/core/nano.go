package core

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type proxySettings struct {
	Server       string   `json:"server"`
	ServerPool   []string `json:"server_pool"`
	Strategy     string   `json:"strategy"`
	Rules        string   `json:"rules"`
	ServerIP     string   `json:"server_ip"`
	Token        string   `json:"token"`
	FallbackAddr string   `json:"fallback_addr,omitempty"`
}

var bufPool = newBufPool(32 * 1024)

func connectNanoTunnel(target string, outboundTag string, payload []byte) (*websocket.Conn, error) {
	settings, ok := getProxySettings(outboundTag)
	if !ok {
		return nil, errors.New("outbound settings not found: " + outboundTag)
	}

	secretKey := settings.Token
	fallback := settings.FallbackAddr

	targetServer := ""
	logLevel := "DIRECT"
	logMsg := ""

	routingMap := getRoutingMap()

	for _, rule := range routingMap {
		if strings.Contains(target, rule.Keyword) {
			targetServer = rule.Node
			logLevel = "RULE"
			logMsg = fmt.Sprintf("规则命中: %-20s → 节点: %s (关键词: %s)",
				target, targetServer, rule.Keyword)
			break
		}
	}

	if targetServer == "" {
		if len(settings.ServerPool) > 0 {
			poolLen := uint64(len(settings.ServerPool))
			strategy := settings.Strategy
			switch strategy {
			case "rr":
				idx := atomic.AddUint64(&globalRRIndex, 1)
				targetServer = settings.ServerPool[idx%poolLen]
			case "hash":
				h := md5.Sum([]byte(target))
				hashVal := binary.BigEndian.Uint64(h[:8])
				targetServer = settings.ServerPool[hashVal%poolLen]
			default:
				targetServer = settings.ServerPool[rand.Intn(int(poolLen))]
			}
			logLevel = "LB"
			logMsg = fmt.Sprintf("负载均衡: %-25s → 节点: %s (策略: %s)",
				target, targetServer, strategy)
		} else {
			targetServer = settings.Server
			logLevel = "DIRECT"
			logMsg = fmt.Sprintf("直连访问: %-25s → 节点: %s",
				target, targetServer)
		}
	}

	emitLog(logLevel, logMsg)

	wsConn, err := dialCleanWebSocket(targetServer, settings.ServerIP, fallback, secretKey)
	if err != nil {
		return nil, err
	}

	if err := sendNanoHeaderV2(wsConn, target, payload, fallback); err != nil {
		wsConn.Close()
		return nil, err
	}

	return wsConn, nil
}

func makePreDialControl() func(network, address string, c syscall.RawConn) error {
	pf := getProtectFunc()
	if pf == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var protectErr error
		ctrlErr := c.Control(func(fd uintptr) {
			if !pf.Protect(int(fd)) {
				protectErr = fmt.Errorf("VpnService.protect(fd=%d) 返回 false", fd)
			}
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return protectErr
	}
}

// smartDialTCP 智能物理拨号器 (优先 IPv4 规避黑洞，完整支持 cf.877774.xyz 优选域名、纯 IP、带端口格式，并对 socket 执行 VPN protect)
func smartDialTCP(targetHostOrIP, defaultPort string, timeout time.Duration) (net.Conn, error) {
	target := strings.TrimSpace(targetHostOrIP)
	host := target
	port := defaultPort

	// 1. 拆解 host 和 port (支持 [2606::1]:443, 1.1.1.1:443, domain.com:443, domain.com)
	if strings.HasPrefix(target, "[") {
		if idx := strings.Index(target, "]"); idx != -1 {
			host = target[1:idx]
			rest := target[idx+1:]
			if strings.HasPrefix(rest, ":") && len(rest) > 1 {
				port = rest[1:]
			}
		}
	} else if strings.Count(target, ":") == 1 {
		if h, p, err := net.SplitHostPort(target); err == nil {
			host = h
			port = p
		}
	} else if strings.Count(target, ":") > 1 {
		host = target
	}

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: makePreDialControl(),
	}

	// 2. 如果本身就是 IP 地址，直接拨号（零 DNS 延迟）
	if ip := net.ParseIP(host); ip != nil {
		return dialer.Dial("tcp", net.JoinHostPort(host, port))
	}

	// 3. 如果是优选域名 (如 cf.877774.xyz)，进行系统 DNS 解析并强制 IPv4 优先
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return dialer.Dial("tcp", net.JoinHostPort(host, port))
	}

	// 排序：IPv4 绝对排在前面，过滤/后置在移动网络中易发生黑洞的 IPv6
	var sortedIPs []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			sortedIPs = append(sortedIPs, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			sortedIPs = append(sortedIPs, ip)
		}
	}

	// 依次尝试候选 IP (单节点 3.5s 快速探测)
	var lastErr error
	singleTimeout := 3500 * time.Millisecond
	if singleTimeout > timeout {
		singleTimeout = timeout
	}

	for _, ip := range sortedIPs {
		singleDialer := &net.Dialer{
			Timeout: singleTimeout,
			Control: makePreDialControl(),
		}
		conn, err := singleDialer.Dial("tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return dialer.Dial("tcp", net.JoinHostPort(host, port))
}

func dialCleanWebSocket(serverAddr, serverIP, fallbackAddr, token string) (*websocket.Conn, error) {
	cleanServerIP := strings.TrimSpace(serverIP)

	parts := strings.SplitN(serverAddr, "#", 2)
	if len(parts) == 2 {
		sni := strings.TrimSpace(parts[0])
		realAddr := strings.TrimSpace(parts[1])

		sniHost, sniPort, err := net.SplitHostPort(sni)
		if err != nil {
			sniHost = sni
			sniPort = "443"
		}

		realTarget := realAddr
		if cleanServerIP != "" {
			realTarget = cleanServerIP
		}

		wsURL := buildWsURL(sniHost, sniPort, token, fallbackAddr)
		reqHeader := http.Header{}
		reqHeader.Add("Host", sniHost)
		reqHeader.Add("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36")
		reqHeader.Add("Authorization", "Bearer "+token)

		dialer := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: sniHost},
			HandshakeTimeout: 10 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				return smartDialTCP(realTarget, p, 8*time.Second)
			},
		}

		conn, resp, err := dialer.Dial(wsURL, reqHeader)
		if err != nil {
			if resp != nil {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil, err
		}
		return conn, nil
	}

	host, port, path, _ := parseServerAddr(serverAddr)

	tlsHost := host
	if strings.HasPrefix(tlsHost, "[") && strings.HasSuffix(tlsHost, "]") {
		tlsHost = tlsHost[1 : len(tlsHost)-1]
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	realTarget := host
	if cleanServerIP != "" {
		realTarget = cleanServerIP
	}

	wsURL := buildWsURL(host+path, port, token, fallbackAddr)
	reqHeader := http.Header{}
	reqHeader.Add("Host", tlsHost)
	reqHeader.Add("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36")
	reqHeader.Add("Authorization", "Bearer "+token)

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: tlsHost},
		HandshakeTimeout: 10 * time.Second,
		NetDial: func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return smartDialTCP(realTarget, p, 8*time.Second)
		},
	}

	conn, resp, err := dialer.Dial(wsURL, reqHeader)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func sendNanoHeaderV2(wsConn *websocket.Conn, target string, payload []byte, fb string) error {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	hostBytes := []byte(host)
	fbBytes := []byte(fb)

	if len(hostBytes) > 255 {
		return errors.New("host length exceeds 255 bytes")
	}
	if len(fbBytes) > 255 {
		return errors.New("fallback address length exceeds 255 bytes")
	}

	buf := new(bytes.Buffer)

	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf.Write(portBytes)

	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	if len(payload) > 0 {
		buf.Write(payload)
	}

	return wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

func buildWsURL(hostWithPath, port, token, fallbackAddr string) string {
	host := hostWithPath
	path := "/"
	if idx := strings.Index(hostWithPath, "/"); idx != -1 {
		path = hostWithPath[idx:]
		host = hostWithPath[:idx]
	}
	base := fmt.Sprintf("wss://%s:%s%s?token=%s",
		host, port, path, url.QueryEscape(token))
	if fallbackAddr != "" {
		base += "&pyip=" + url.QueryEscape(fallbackAddr)
	}
	return base
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
		err = nil
	}
	return
}