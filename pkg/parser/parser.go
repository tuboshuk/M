package parser

import (
	"regexp"
	"strings"

	"mdns-mapper/pkg/banner"
	"mdns-mapper/pkg/models"
)

// ProtocolParser 协议解析器
type ProtocolParser struct{}

// NewProtocolParser 创建协议解析器
func NewProtocolParser() *ProtocolParser {
	return &ProtocolParser{}
}

// Parse 解析 Banner 数据
func (p *ProtocolParser) Parse(serviceType string, grabResult *banner.GrabResult, mdnsData map[string][]string) models.ServiceBanner {
	banner := models.ServiceBanner{}

	if grabResult != nil {
		banner.RawBanner = grabResult.RawData
		
		switch grabResult.Protocol {
		case "http":
			banner = p.parseHTTP(grabResult, banner)
		case "smb":
			banner = p.parseSMB(grabResult, banner)
		case "ssh":
			banner = p.parseSSH(grabResult, banner)
		case "ftp":
			banner = p.parseFTP(grabResult, banner)
		case "afp":
			banner = p.parseAFP(grabResult, banner)
		default:
			banner = p.parseGeneric(grabResult, banner)
		}
	}

	// 从 mDNS 数据中提取信息
	banner = p.enrichFromMDNS(banner, mdnsData)

	return banner
}

// parseHTTP 解析 HTTP Banner
func (p *ProtocolParser) parseHTTP(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	if server, ok := grabResult.Extra["server"]; ok {
		banner.Server = server
		if banner.Name == "" {
			banner.Name = server
		}
	}

	if title, ok := grabResult.Extra["title"]; ok {
		banner.Title = title
	}

	if path, ok := grabResult.Extra["path"]; ok {
		banner.Path = path
	}

	return banner
}

// parseSMB 解析 SMB Banner
func (p *ProtocolParser) parseSMB(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	if domain, ok := grabResult.Extra["domain"]; ok {
		banner.Domain = domain
	}

	if os, ok := grabResult.Extra["os"]; ok {
		banner.OS = os
	}

	// 从原始数据中提取更多信息
	if strings.Contains(grabResult.RawData, "WORKGROUP") {
		banner.Domain = "WORKGROUP"
	}

	return banner
}

// parseSSH 解析 SSH Banner
func (p *ProtocolParser) parseSSH(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	banner.Service = "ssh"
	
	if version, ok := grabResult.Extra["version"]; ok {
		banner.Name = "SSH-" + version
	}

	if software, ok := grabResult.Extra["software"]; ok {
		if banner.Name == "" {
			banner.Name = software
		}
	}

	return banner
}

// parseFTP 解析 FTP Banner
func (p *ProtocolParser) parseFTP(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	banner.Service = "ftp"
	
	if bannerStr, ok := grabResult.Extra["banner"]; ok {
		banner.Name = bannerStr
	}

	return banner
}

// parseAFP 解析 AFP Banner
func (p *ProtocolParser) parseAFP(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	banner.Service = "afpovertcp"
	
	// AFP 协议解析需要更深入的数据包分析
	// 这里做简化处理
	banner.Name = "AFP Server"

	return banner
}

// parseGeneric 解析通用 Banner
func (p *ProtocolParser) parseGeneric(grabResult *banner.GrabResult, banner models.ServiceBanner) models.ServiceBanner {
	banner.Service = grabResult.Protocol
	
	// 尝试从原始 Banner 中提取信息
	lines := strings.Split(grabResult.RawData, "\n")
	if len(lines) > 0 {
		banner.Name = strings.TrimSpace(lines[0])
	}

	return banner
}

// enrichFromMDNS 从 mDNS 数据丰富 Banner 信息
func (p *ProtocolParser) enrichFromMDNS(banner models.ServiceBanner, mdnsData map[string][]string) models.ServiceBanner {
	// 解析 TXT 记录
	if txtRecords, ok := mdnsData["txt"]; ok {
		for _, txt := range txtRecords {
			// 解析 key=value 格式
			if strings.Contains(txt, "=") {
				parts := strings.SplitN(txt, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])

					switch key {
					case "name":
						if banner.Name == "" {
							banner.Name = value
						}
					case "model":
						banner.Model = value
					case "machine_type":
						banner.MachineType = value
					case "fwVer":
						banner.FWVer = value
					case "accessType":
						banner.AccessType = value
					case "accessPort":
						banner.AccessPort = value
					case "displayModel":
						banner.DisplayModel = value
					case "fwBuildNum":
						banner.FWBuildNum = value
					default:
						// 其他字段存入 ExtraFields
						if banner.ExtraFields == nil {
							banner.ExtraFields = make(map[string]string)
						}
						banner.ExtraFields[key] = value
					}
				}
			} else {
				// 非 key=value 格式，可能是名称
				if banner.Name == "" && len(txt) > 0 {
					banner.Name = txt
				}
			}
		}
	}

	// 解析 SRV 记录获取主机名
	if srvRecords, ok := mdnsData["srv"]; ok {
		for _, srv := range srvRecords {
			// 提取主机名
			if strings.Contains(srv, ".local") {
				parts := strings.Split(srv, ".")
				if len(parts) > 0 {
					if banner.Name == "" {
						banner.Name = parts[0]
					}
				}
			}
		}
	}

	return banner
}

// ParseWorkstation 解析 Workstation 服务
func (p *ProtocolParser) ParseWorkstation(mdnsData map[string][]string) models.ServiceBanner {
	banner := models.ServiceBanner{
		Service: "workstation",
	}

	return p.enrichFromMDNS(banner, mdnsData)
}

// ParseDevice 解析 Device-Info 服务
func (p *ProtocolParser) ParseDevice(mdnsData map[string][]string) models.ServiceBanner {
	banner := models.ServiceBanner{
		Service: "device-info",
	}

	// 从 TXT 记录提取设备信息
	if txtRecords, ok := mdnsData["txt"]; ok {
		for _, txt := range txtRecords {
			if strings.Contains(txt, "=") {
				parts := strings.SplitN(txt, "=", 2)
				if len(parts) == 2 {
					key := parts[0]
					value := parts[1]

					if key == "model" || key == "Model" {
						banner.Model = value
					} else if key == "name" || key == "Name" {
						banner.Name = value
					}
				}
			}
		}
	}

	return p.enrichFromMDNS(banner, mdnsData)
}

// ParseQDiscover 解析 QDiscover 服务 (QNAP)
func (p *ProtocolParser) ParseQDiscover(mdnsData map[string][]string) models.ServiceBanner {
	banner := models.ServiceBanner{
		Service: "qdiscover",
	}

	// 解析 QNAP 特定的 TXT 记录
	if txtRecords, ok := mdnsData["txt"]; ok {
		for _, txt := range txtRecords {
			if strings.Contains(txt, "=") {
				parts := strings.SplitN(txt, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])

					switch key {
					case "accessType":
						banner.AccessType = value
					case "accessPort":
						banner.AccessPort = value
					case "model":
						banner.Model = value
					case "displayModel":
						banner.DisplayModel = value
					case "fwVer":
						banner.FWVer = value
					case "fwBuildNum":
						banner.FWBuildNum = value
					}
				}
			}
		}
	}

	return p.enrichFromMDNS(banner, mdnsData)
}

// ExtractMAC 从 mDNS 数据中提取 MAC 地址
func (p *ProtocolParser) ExtractMAC(mdnsData map[string][]string) string {
	// 尝试从各种记录中提取 MAC 地址
	macPattern := regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)

	for _, records := range mdnsData {
		for _, record := range records {
			matches := macPattern.FindString(record)
			if matches != "" {
				return matches
			}
		}
	}

	return ""
}

// ParseServiceName 从服务类型解析服务名称
func (p *ProtocolParser) ParseServiceName(serviceType string) string {
	// 移除 ._tcp.local 或 ._udp.local 后缀
	serviceType = strings.TrimSuffix(serviceType, "._tcp.local")
	serviceType = strings.TrimSuffix(serviceType, "._udp.local")
	serviceType = strings.TrimPrefix(serviceType, "_")

	return serviceType
}
