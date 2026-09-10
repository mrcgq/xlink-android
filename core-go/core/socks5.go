package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// handleSOCKS5 完成 SOCKS5 握手并解析目标地址
func handleSOCKS5(conn net.Conn) (string, error) {
	// 1. 协商认证方法
	nMethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, nMethodsBuf); err != nil {
		return "", fmt.Errorf("socks5: read nmethods: %w", err)
	}

	methods := make([]byte, nMethodsBuf[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("socks5: read methods: %w", err)
	}

	// 回复无需认证: 0x05 0x00
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("socks5: write auth response: %w", err)
	}

	// 2. 解析请求报文
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("socks5: read request header: %w", err)
	}

	if header[0] != 0x05 {
		return "", fmt.Errorf("socks5: unsupported version: %d", header[0])
	}
	if header[1] != 0x01 { // 仅处理 TCP CONNECT
		return "", fmt.Errorf("socks5: unsupported cmd: %d", header[1])
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(b).String()

	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("socks5: read domain len: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(domain)

	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(b).String()

	default:
		return "", fmt.Errorf("socks5: unsupported address type: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", fmt.Errorf("socks5: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// sendSocks5SuccessResponse 回复 RFC 1928 成功响应 (解决卡死不通的关键)
func sendSocks5SuccessResponse(conn net.Conn) error {
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(resp)
	return err
}

// sendSocks5ErrorResponse 回复 SOCKS5 错误
func sendSocks5ErrorResponse(conn net.Conn, rep byte) {
	resp := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _ = conn.Write(resp)
}