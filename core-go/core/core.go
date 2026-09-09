package core

import (
	"encoding/json"
	"net"
	"sync"
)

var (
	globalMutex     sync.Mutex
	globalRunning   bool
	globalNodeTag   string
	globalLogCb     LogCallback
	globalProtectFn ProtectFunc
	globalRRIndex   uint64
	currentSettings map[string]ProxySettings
	currentRouting  []Rule
	listener        net.Listener
)

type LogCallback interface {
	OnLog(level, nodeTag, message string)
}

type ProtectFunc interface {
	Protect(fd int) bool
}

func SetLogCallback(cb LogCallback) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalLogCb = cb
}

func SetProtectFunc(pf ProtectFunc) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalProtectFn = pf
}

func SetNodeTag(tag string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalNodeTag = tag
}

func IsRunning() bool {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalRunning
}

func getProtectFunc() ProtectFunc {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalProtectFn
}

func getProxySettings(tag string) (ProxySettings, bool) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if currentSettings == nil {
		return ProxySettings{}, false
	}
	s, ok := currentSettings[tag]
	return s, ok
}

func getRoutingMap() []Rule {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return currentRouting
}

func emitLog(level, msg string) {
	globalMutex.Lock()
	cb := globalLogCb
	tag := globalNodeTag
	globalMutex.Unlock()
	if cb != nil {
		cb.OnLog(level, tag, msg)
	}
}

func Start(configJSON string) string {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalRunning {
		return "already running"
	}

	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "parse config failed: " + err.Error()
	}

	newSettings := make(map[string]ProxySettings)
	for _, ob := range cfg.Outbounds {
		if ob.Protocol == "ech-proxy" {
			var ps ProxySettings
			if err := json.Unmarshal(ob.Settings, &ps); err == nil {
				newSettings[ob.Tag] = ps
				if ps.Rules != "" {
					currentRouting = parseRulesString(ps.Rules)
				}
			}
		}
	}
	currentSettings = newSettings

	listenAddr := "127.0.0.1:10808"
	if len(cfg.Inbounds) > 0 && cfg.Inbounds[0].Listen != "" {
		listenAddr = cfg.Inbounds[0].Listen
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "listen failed: " + err.Error()
	}
	listener = l
	globalRunning = true

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				break
			}
			go handleIncoming(conn)
		}
	}()

	emitLog("SYSTEM", "SOCKS5 引擎已成功监听: "+listenAddr)
	return ""
}

func handleIncoming(conn net.Conn) {
	defer conn.Close()
	target, err := handleSOCKS5(conn)
	if err != nil {
		emitLog("ERROR", "SOCKS5 握手失败: "+err.Error())
		return
	}

	wsConn, err := connectNanoTunnel(target, "proxy", nil)
	if err != nil {
		emitLog("ERROR", "连接远程节点失败: "+err.Error())
		return
	}
	defer wsConn.Close()

	pipeDirect(conn, wsConn)
}

func Stop() {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if !globalRunning {
		return
	}
	globalRunning = false
	if listener != nil {
		listener.Close()
		listener = nil
	}
	emitLog("SYSTEM", "引擎已停止")
}