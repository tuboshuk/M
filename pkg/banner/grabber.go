package banner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Grabber Banner 抓取器
type Grabber struct {
	timeout time.Duration
	verbose bool
}

// NewGrabber 创建 Banner 抓取器
func NewGrabber(timeout time.Duration, verbose bool) *Grabber {
	return &Grabber{
		timeout: timeout,
		verbose: verbose,
	}
}

// GrabResult 抓取结果
type GrabResult struct {
	Protocol string
	RawData  string
	Extra    map[string]string
}

// Grab 抓取指定端口的 Banner
func (g *Grabber) Grab(ctx context.Context, ip string, port int) (*GrabResult, error) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// 首先尝试 HTTP/HTTPS
	if result := g.grabHTTP(address); result != nil {
		return result, nil
	}

	// 尝试 SMB (445)
	if port == 445 {
		if result := g.grabSMB(address); result != nil {
			return result, nil
		}
	}

	// 尝试 SSH (22)
	if port == 22 {
		if result := g.grabSSH(address); result != nil {
			return result, nil
		}
	}

	// 尝试 FTP (21)
	if port == 21 {
		if result := g.grabFTP(address); result != nil {
			return result, nil
		}
	}

	// 尝试 AFP (548)
	if port == 548 {
		if result := g.grabAFP(address); result != nil {
			return result, nil
		}
	}

	// 通用 Banner 抓取
	result := g.grabGeneric(address)
	return result, nil
}

// grabHTTP 抓取 HTTP/HTTPS Banner
func (g *Grabber) grabHTTP(address string) *GrabResult {
	// 尝试 HTTP
	httpURL := "http://" + address
	if result := g.fetchHTTP(httpURL); result != nil {
		return result
	}

	// 尝试 HTTPS
	httpsURL := "https://" + address
	if result := g.fetchHTTP(httpsURL); result != nil {
		return result
	}

	return nil
}

// fetchHTTP 发送 HTTP 请求
func (g *Grabber) fetchHTTP(url string) *GrabResult {
	client := &http.Client{
		Timeout: g.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result := &GrabResult{
		Protocol: "http",
		Extra:    make(map[string]string),
	}

	// 提取 Server 头
	if server := resp.Header.Get("Server"); server != "" {
		result.Extra["server"] = server
	}

	// 提取 Title
	title, err := g.extractTitle(resp.Body)
	if err == nil && title != "" {
		result.Extra["title"] = title
	}

	// 提取路径
	result.Extra["path"] = "/"

	// 构建原始 Banner
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", resp.StatusCode, resp.Status))
	for key, values := range resp.Header {
		for _, value := range values {
			builder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	result.RawData = builder.String()

	return result
}

// extractTitle 提取 HTML 标题
func (g *Grabber) extractTitle(reader interface{}) (string, error) {
	// 简单实现，实际应该解析 HTML
	data, ok := reader.(*http.Response)
	if !ok {
		return "", fmt.Errorf("invalid type")
	}

	buf := make([]byte, 8192)
	n, err := data.Body.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}

	content := string(buf[:n])
	
	// 使用正则表达式提取 title
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}

	return "", nil
}

// grabSMB 抓取 SMB Banner
func (g *Grabber) grabSMB(address string) *GrabResult {
	conn, err := net.DialTimeout("tcp", address, g.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// SMB Negotiate Protocol Request
	negotiateRequest := []byte{
		0x00, 0x00, 0x00, 0x54, // NetBIOS Session Service
		0xff, 0x53, 0x4d, 0x42, // SMB Protocol
		0x72, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xfe,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x62, 0x00, 0x02,
		0x50, 0x43, 0x20, 0x4e,
		0x45, 0x54, 0x57, 0x4f,
		0x52, 0x4b, 0x20, 0x50,
		0x52, 0x4f, 0x47, 0x52,
		0x41, 0x4d, 0x20, 0x31,
		0x2e, 0x30, 0x00, 0x02,
		0x4c, 0x41, 0x4e, 0x4d,
		0x41, 0x4e, 0x31, 0x2e,
		0x30, 0x00, 0x02, 0x57,
		0x69, 0x6e, 0x64, 0x6f,
		0x77, 0x73, 0x20, 0x66,
		0x6f, 0x72, 0x20, 0x57,
		0x6f, 0x72, 0x6b, 0x67,
		0x72, 0x6f, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2e,
		0x31, 0x61, 0x00, 0x02,
		0x4c, 0x4d, 0x31, 0x2e,
		0x32, 0x58, 0x30, 0x30,
		0x32, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(g.timeout))
	_, err = conn.Write(negotiateRequest)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(g.timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	result := &GrabResult{
		Protocol: "smb",
		RawData:  fmt.Sprintf("%x", buf[:n]),
		Extra:    make(map[string]string),
	}

	// 尝试解析 SMB 响应
	if n > 36 {
		// 提取域名和工作组信息（简化实现）
		result.Extra["dialect"] = "SMB1"
	}

	return result
}

// grabSSH 抓取 SSH Banner
func (g *Grabber) grabSSH(address string) *GrabResult {
	conn, err := net.DialTimeout("tcp", address, g.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(g.timeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if !strings.HasPrefix(line, "SSH-") {
		return nil
	}

	result := &GrabResult{
		Protocol: "ssh",
		RawData:  strings.TrimSpace(line),
		Extra:    make(map[string]string),
	}

	// 解析 SSH 版本
	parts := strings.Split(line, "-")
	if len(parts) >= 3 {
		result.Extra["version"] = parts[1]
		if len(parts) > 3 {
			result.Extra["software"] = strings.Join(parts[2:], "-")
		}
	}

	return result
}

// grabFTP 抓取 FTP Banner
func (g *Grabber) grabFTP(address string) *GrabResult {
	conn, err := net.DialTimeout("tcp", address, g.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(g.timeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if !strings.HasPrefix(line, "220") {
		return nil
	}

	result := &GrabResult{
		Protocol: "ftp",
		RawData:  strings.TrimSpace(line),
		Extra:    make(map[string]string),
	}

	// 提取 FTP 服务器信息
	result.Extra["banner"] = strings.TrimSpace(line[4:])

	return result
}

// grabAFP 抓取 AFP Banner (简化实现)
func (g *Grabber) grabAFP(address string) *GrabResult {
	conn, err := net.DialTimeout("tcp", address, g.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// AFP OpenSession 请求
	openSession := []byte{
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(g.timeout))
	_, err = conn.Write(openSession)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(g.timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	result := &GrabResult{
		Protocol: "afp",
		RawData:  fmt.Sprintf("%x", buf[:n]),
		Extra:    make(map[string]string),
	}

	return result
}

// grabGeneric 通用 Banner 抓取
func (g *Grabber) grabGeneric(address string) *GrabResult {
	conn, err := net.DialTimeout("tcp", address, g.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(g.timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	result := &GrabResult{
		Protocol: "unknown",
		RawData:  string(buf[:n]),
		Extra:    make(map[string]string),
	}

	// 尝试识别协议类型
	data := string(buf[:n])
	if strings.Contains(data, "HTTP") {
		result.Protocol = "http"
	} else if strings.Contains(data, "SSH") {
		result.Protocol = "ssh"
	} else if strings.Contains(data, "FTP") {
		result.Protocol = "ftp"
	} else if strings.Contains(data, "SMB") {
		result.Protocol = "smb"
	}

	return result
}
