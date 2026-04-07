package parser

import (
	"regexp"
	"strings"
)

// Parser 协议解析器接口
type Parser interface {
	Parse(banner string) map[string]string
}

// NewParser 根据协议类型创建解析器
func NewParser(protocol string) Parser {
	switch protocol {
	case "http":
		return &HTTPParser{}
	case "smb":
		return &SMBParser{}
	case "afp":
		return &AFPParser{}
	case "ssh":
		return &SSHParser{}
	case "ftp":
		return &FTPParser{}
	default:
		return &DefaultParser{}
	}
}

// HTTPParser HTTP协议解析器
type HTTPParser struct{}

// Parse 解析HTTP Banner
func (p *HTTPParser) Parse(banner string) map[string]string {
	result := make(map[string]string)

	// 解析状态码
	statusRegex := regexp.MustCompile(`HTTP/\d\.\d\s+(\d+)\s+(.+)`)
	if matches := statusRegex.FindStringSubmatch(banner); len(matches) > 2 {
		result["status"] = matches[1]
		result["status_text"] = matches[2]
	}

	// 解析Server头
	serverRegex := regexp.MustCompile(`Server:\s*(.+)`)
	if matches := serverRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["server"] = matches[1]
	}

	// 解析Content-Type
	contentTypeRegex := regexp.MustCompile(`Content-Type:\s*(.+)`)
	if matches := contentTypeRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["content_type"] = matches[1]
	}

	// 解析Title
	titleRegex := regexp.MustCompile(`<title>(.+)</title>`)
	if matches := titleRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["title"] = matches[1]
	}

	// 解析路径
	pathRegex := regexp.MustCompile(`GET\s+([^\s]+)\s+HTTP`)
	if matches := pathRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["path"] = matches[1]
	}

	return result
}

// SMBParser SMB协议解析器
type SMBParser struct{}

// Parse 解析SMB Banner
func (p *SMBParser) Parse(banner string) map[string]string {
	result := make(map[string]string)

	// 解析SMB版本
	smbRegex := regexp.MustCompile(`SMB(\d+\.\d+)`)
	if matches := smbRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["version"] = matches[1]
	}

	// 解析服务器信息
	if strings.Contains(banner, "Microsoft") {
		result["os"] = "Windows"
	}
	if strings.Contains(banner, "Samba") {
		result["os"] = "Unix/Linux"
		result["server"] = "Samba"
	}

	return result
}

// AFPParser AFP协议解析器
type AFPParser struct{}

// Parse 解析AFP Banner
func (p *AFPParser) Parse(banner string) map[string]string {
	result := make(map[string]string)

	// 解析AFP版本
	afRegex := regexp.MustCompile(`AFP(\d+\.\d+)`)
	if matches := afRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["version"] = matches[1]
	}

	// 解析服务器名称
	nameRegex := regexp.MustCompile(`Server:\s*(.+)`)
	if matches := nameRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["name"] = matches[1]
	}

	return result
}

// SSHParser SSH协议解析器
type SSHParser struct{}

// Parse 解析SSH Banner
func (p *SSHParser) Parse(banner string) map[string]string {
	result := make(map[string]string)

	// 解析SSH版本
	sshRegex := regexp.MustCompile(`SSH-(\d+\.\d+)-(.*)`)
	if matches := sshRegex.FindStringSubmatch(banner); len(matches) > 2 {
		result["version"] = matches[1]
		result["software"] = matches[2]
	}

	return result
}

// FTPParser FTP协议解析器
type FTPParser struct{}

// Parse 解析FTP Banner
func (p *FTPParser) Parse(banner string) map[string]string {
	result := make(map[string]string)

	// 解析FTP服务器信息
	ftpRegex := regexp.MustCompile(`220\s+(.+)`)
	if matches := ftpRegex.FindStringSubmatch(banner); len(matches) > 1 {
		result["banner"] = matches[1]
	}

	// 解析服务器类型
	if strings.Contains(banner, "ProFTPD") {
		result["server"] = "ProFTPD"
	} else if strings.Contains(banner, "vsftpd") {
		result["server"] = "vsftpd"
	} else if strings.Contains(banner, "FileZilla") {
		result["server"] = "FileZilla"
	} else if strings.Contains(banner, "Microsoft") {
		result["server"] = "Microsoft FTP"
	}

	return result
}

// DefaultParser 默认解析器
type DefaultParser struct{}

// Parse 默认解析
func (p *DefaultParser) Parse(banner string) map[string]string {
	result := make(map[string]string)
	result["raw"] = banner
	return result
}
