------------------------------------------------------------
package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}

type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
}

type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}

type Rule struct {
	Keyword string
	Node    string
}

func parseRulesString(raw string) []Rule {
	var rules []Rule

	raw = strings.ReplaceAll(raw, "|", "\n")
	raw = strings.ReplaceAll(raw, ";", "\n")
	raw = strings.ReplaceAll(raw, "；", "\n")
	raw = strings.ReplaceAll(raw, "\r", "")

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, "，", ",")
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			keyword := strings.TrimSpace(parts[0])
			node := strings.TrimRight(strings.TrimSpace(parts[1]), ";,.")
			if keyword != "" && node != "" {
				rules = append(rules, Rule{Keyword: keyword, Node: node})
			}
		}
	}
	return rules
}

func GenerateConfigJSON(
	serverAddr, serverIP, secretKey,
	fallbackAddr, listenAddr,
	strategy, rules string,
) string {
	cleanListen := strings.TrimSpace(
		strings.ReplaceAll(strings.ReplaceAll(listenAddr, "\r", ""), "\n", ""),
	)

	normalizedAddr := serverAddr
	for _, r := range []string{"\r\n", "\n", "，", ",", "；"} {
		normalizedAddr = strings.ReplaceAll(normalizedAddr, r, ";")
	}

	var serverJSON string
	if strings.Contains(normalizedAddr, ";") {
		rawPool := strings.Split(normalizedAddr, ";")
		var validPool []string
		for _, node := range rawPool {
			if t := strings.TrimSpace(node); t != "" {
				validPool = append(validPool, t)
			}
		}
		switch len(validPool) {
		case 0:
			serverJSON = `"server": ""`
		case 1:
			nodeJSON, _ := json.Marshal(validPool[0])
			serverJSON = fmt.Sprintf(`"server": %s`, string(nodeJSON))
		default:
			poolJSON, _ := json.Marshal(validPool)
			firstJSON, _ := json.Marshal(validPool[0])
			strategyJSON, _ := json.Marshal(strategy)
			serverJSON = fmt.Sprintf(
				`"server": %s, "server_pool": %s, "strategy": %s`,
				string(firstJSON), string(poolJSON), string(strategyJSON))
		}
	} else {
		nodeJSON, _ := json.Marshal(strings.TrimSpace(serverAddr))
		serverJSON = fmt.Sprintf(`"server": %s`, string(nodeJSON))
	}

	listenJSON, _ := json.Marshal(cleanListen)
	tokenJSON, _ := json.Marshal(secretKey)
	rulesJSON, _ := json.Marshal(rules)

	serverIPJSON := ""
	if serverIP != "" {
		sipJSON, _ := json.Marshal(serverIP)
		serverIPJSON = fmt.Sprintf(`, "server_ip": %s`, string(sipJSON))
	}

	fallbackJSON := ""
	if fallbackAddr != "" {
		fbJSON, _ := json.Marshal(fallbackAddr)
		fallbackJSON = fmt.Sprintf(`, "fallback_addr": %s`, string(fbJSON))
	}

	config := fmt.Sprintf(
		`{`+
			`"inbounds": [{"tag": "socks-in", "listen": %s, "protocol": "socks"}],`+
			`"outbounds": [{`+
			`"tag": "proxy",`+
			`"protocol": "ech-proxy",`+
			`"settings": {`+
			`%s,`+
			`"token": %s,`+
			`"rules": %s%s%s`+
			`}`+
			`}],`+
			`"routing": {"rules": [{"outboundTag": "proxy", "port": [0, 65535]}]}`+
			`}`,
		string(listenJSON),
		serverJSON,
		string(tokenJSON),
		string(rulesJSON),
		serverIPJSON,
		fallbackJSON,
	)

	return config
}

func Version() string {
	return "14.2-android"
}
