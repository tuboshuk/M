package banner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// Banner Banner信息
type Banner struct {
	Raw      string
	Protocol string
}

// Grabber Banner抓取器
type Grabber struct {
	Timeout time.Duration
}

// NewGrabber 创建新的Banner抓取器
func NewGrabber(timeout time.Duration) *Grabber {
	return &Grabber{
		Timeout: timeout,
	}
}

// Grab 抓取指定IP和端口的Banner
func (g *Grabber) Grab(ip string, port int) (*Banner, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", addr, g.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(g.Timeout))

	// 读取Banner
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		// 如果读取失败，尝试发送一些常见协议的请求
		return g.tryCommonProtocols(conn, reader, ip, port)
	}

	banner := &Banner{
		Raw:      strings.TrimSpace(string(buffer[:n])),
		Protocol: g.detectProtocol(string(buffer[:n]), port),
	}

	return banner, nil
}

// tryCommonProtocols 尝试常见协议的请求
func (g *Grabber) tryCommonProtocols(conn net.Conn, reader *bufio.Reader, ip string, port int) (*Banner, error) {
	// 尝试HTTP请求
	httpBanner, err := g.tryHTTP(conn, reader)
	if err == nil {
		return httpBanner, nil
	}

	// 尝试SMB请求
	smbBanner, err := g.trySMB(conn, reader)
	if err == nil {
		return smbBanner, nil
	}

	// 尝试SSH请求
	sshBanner, err := g.trySSH(conn, reader)
	if err == nil {
		return sshBanner, nil
	}

	// 尝试FTP请求
	ftpBanner, err := g.tryFTP(conn, reader)
	if err == nil {
		return ftpBanner, nil
	}

	// 尝试AFP请求
	afpHanner, err := g.tryAFP(conn, reader)
	if err == nil {
		return afpHanner, nil
	}

	return nil, fmt.Errorf("无法获取Banner")
}

// tryHTTP 尝试HTTP请求
func (g *Grabber) tryHTTP(conn net.Conn, reader *bufio.Reader) (*Banner, error) {
	request := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	_, err := conn.Write([]byte(request))
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, err
	}

	return &Banner{
		Raw:      strings.TrimSpace(string(buffer[:n])),
		Protocol: "http",
	}, nil
}

// trySMB 尝试SMB请求
func (g *Grabber) trySMB(conn net.Conn, reader *bufio.Reader) (*Banner, error) {
	// SMB Negotiate Protocol Request
	request := []byte{0x00, 0x00, 0x00, 0x54, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(request)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, err
	}

	return &Banner{
		Raw:      strings.TrimSpace(string(buffer[:n])),
		Protocol: "smb",
	}, nil
}

// trySSH 尝试SSH请求
func (g *Grabber) trySSH(conn net.Conn, reader *bufio.Reader) (*Banner, error) {
	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(string(buffer[:n]), "SSH-") {
		return &Banner{
			Raw:      strings.TrimSpace(string(buffer[:n])),
			Protocol: "ssh",
		}, nil
	}

	return nil, fmt.Errorf("不是SSH协议")
}

// tryFTP 尝试FTP请求
func (g *Grabber) tryFTP(conn net.Conn, reader *bufio.Reader) (*Banner, error) {
	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(string(buffer[:n]), "220 ") {
		return &Banner{
			Raw:      strings.TrimSpace(string(buffer[:n])),
			Protocol: "ftp",
		}, nil
	}

	return nil, fmt.Errorf("不是FTP协议")
}

// tryAFP 尝试AFP请求
func (g *Grabber) tryAFP(conn net.Conn, reader *bufio.Reader) (*Banner, error) {
	// AFP GetInfo Request
	request := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01}
	_, err := conn.Write(request)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, err
	}

	return &Banner{
		Raw:      strings.TrimSpace(string(buffer[:n])),
		Protocol: "afp",
	}, nil
}

// detectProtocol 根据Banner和端口检测协议
func (g *Grabber) detectProtocol(banner string, port int) string {
	// 根据端口判断
	switch port {
	case 80, 8080, 8000, 8888:
		return "http"
	case 443, 8443:
		return "https"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 445, 139:
		return "smb"
	case 548:
		return "afp"
	case 3389:
		return "rdp"
	case 25:
		return "smtp"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	}

	// 根据Banner内容判断
	if strings.HasPrefix(banner, "HTTP/") {
		return "http"
	}
	if strings.HasPrefix(banner, "SSH-") {
		return "ssh"
	}
	if strings.HasPrefix(banner, "220 ") {
		return "ftp"
	}
	if strings.Contains(banner, "SMB") || strings.Contains(banner, "Microsoft") {
		return "smb"
	}
	if strings.Contains(banner, "AFP") {
		return "afp"
	}

	return "unknown"
}
