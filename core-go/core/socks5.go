------------------------------------------------------------
package core

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func handleSOCKS5(conn net.Conn) (string, error) {
	nMethodsBuf := make([]byte, 1)
	if _, err := readFull(conn, nMethodsBuf); err != nil {
		return "", fmt.Errorf("socks5: read nmethods: %w", err)
	}

	methods := make([]byte, nMethodsBuf[0])
	if _, err := readFull(conn, methods); err != nil {
		return "", fmt.Errorf("socks5: read methods: %w", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("socks5: write auth response: %w", err)
	}

	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return "", fmt.Errorf("socks5: read request header: %w", err)
	}

	var host string
	switch header[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := readFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(b).String()

	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := readFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("socks5: read domain len: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := readFull(conn, domain); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(domain)

	case 0x04:
		b := make([]byte, 16)
		if _, err := readFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(b).String()

	default:
		return "", fmt.Errorf("socks5: unsupported address type: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := readFull(conn, portBytes); err != nil {
		return "", fmt.Errorf("socks5: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", nil, 0, err
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	if req.Method == "CONNECT" {
		return target, nil, 2, nil
	}

	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

func readFull(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}
