# mDNS Asset Mapper Skill

## 功能描述

mDNS Asset Mapper Skill 是一个基于 Golang 开发的网络资产发现工具，专门用于扫描指定 IP 网段和端口范围，识别 mDNS 协议资产并深度解析 Banner 信息。

## 核心功能

- **端口扫描**：支持扫描指定 IP 网段和端口范围，支持 CIDR 格式和端口范围表示
- **mDNS 服务发现**：识别运行 mDNS 协议的资产，获取 PTR、SRV、TXT、A、AAAA 等记录
- **Banner 深度解析**：支持 HTTP、SMB、AFP、SSH、FTP 等协议的深度解析
- **多格式输出**：支持 YAML、JSON、Table 格式输出
- **并发扫描**：可配置并发数，提高扫描速度

## 技术实现

- **语言**：Go 1.25+
- **核心依赖**：
  - github.com/miekg/dns - DNS/mDNS 协议支持
  - github.com/spf13/cobra - CLI 框架
  - gopkg.in/yaml.v3 - YAML 输出
  - github.com/fatih/color - 彩色输出

## 集成方式

### 1. 作为独立工具使用

```bash
# 编译
cd mdns-mapper
go build -o mdns-mapper.exe ./cmd

# 运行
./mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000
```

### 2. 作为库集成到其他项目

```go
import (
	"time"

	"mdns-mapper/internal/scanner"
	"mdns-mapper/internal/mdns"
	"mdns-mapper/internal/banner"
	"mdns-mapper/internal/parser"
	"mdns-mapper/internal/output"
)

// 初始化扫描器
scan := scanner.NewScanner("192.168.1.0/24", "1-1000", 2*time.Second, 50)

// 执行扫描
results, err := scan.Scan()
if err != nil {
	// 处理错误
}

// 处理扫描结果
for _, result := range results {
	// Banner抓取
	grabber := banner.NewGrabber(2*time.Second)
	bannerInfo, err := grabber.Grab(result.IP, result.Port)
	if err != nil {
		continue
	}

	// 协议解析
	parser := parser.NewParser(bannerInfo.Protocol)
	parsedBanner := parser.Parse(bannerInfo.Raw)

	// mDNS探测
	probe := mdns.NewProbe(2*time.Second)
	mdnsRecord, err := probe.Discover(result.IP)
	if err == nil {
		// 处理mDNS记录
	}
}
```

## 配置参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| --cidr | -c | IP 网段（支持多个，逗号分隔） | 必填 |
| --ports | -p | 端口范围（如 1-1000,8080,9000） | 必填 |
| --timeout | -t | 连接超时（默认 2s） | 2s |
| --concurrency | -C | 并发数（默认 50） | 50 |
| --output | -o | 输出格式（yaml/json/table） | yaml |
| --verbose | -v | 详细输出模式 | false |

## 输出格式

### YAML 格式

```yaml
scan_info:
  cidr: 192.168.1.0/24
  ports: 1-1000
  timestamp: 2026-04-07T12:00:00Z
  duration: 45s

assets:
  - ip: 192.168.1.100
    mac: 24:5e:be:69:a3:13
    hostname: slw-nas.local
    services:
      - port: 9
        protocol: tcp
        service: workstation
        banner:
          name: slw-nas
          ttl: 10
```

### JSON 格式

```json
{
  "scan_info": {
    "cidr": "192.168.1.0/24",
    "ports": "1-1000",
    "timestamp": "2026-04-07T12:00:00Z",
    "duration": "45s"
  },
  "assets": [
    {
      "ip": "192.168.1.100",
      "mac": "24:5e:be:69:a3:13",
      "hostname": "slw-nas.local",
      "services": [
        {
          "port": 9,
          "protocol": "tcp",
          "service": "workstation",
          "banner": {
            "name": "slw-nas",
            "ttl": 10
          }
        }
      ]
    }
  ]
}
```

### Table 格式

```
=== Scan Information ===
CIDR:     192.168.1.0/24
Ports:    1-1000
Time:     2026-04-07 12:00:00
Duration: 45s

=== Assets ===

[+] 192.168.1.100 [24:5e:be:69:a3:13] (slw-nas.local)
    9/tcp workstation:
        Name=slw-nas
        TTL=10
```

## 支持的协议

### mDNS 服务类型
- _workstation._tcp.local
- _http._tcp.local
- _https._tcp.local
- _smb._tcp.local
- _afpovertcp._tcp.local
- _ssh._tcp.local
- _ftp._tcp.local
- _device-info._tcp.local
- _qdiscover._tcp.local (QNAP 设备)

### Banner 深度解析
- **HTTP/HTTPS**: Server 头、Title、路径
- **SMB**: 主机名、域名、OS 版本
- **SSH**: 版本信息、软件信息
- **FTP**: Banner 信息
- **AFP**: 服务器名称、型号
- **通用协议**: 原始 Banner 提取

## 性能指标

- 扫描速度：/24 网段 + 1000 端口 ≤ 5 分钟（百兆网络）
- 并发能力：支持 10-500 可配并发数
- 内存占用：≤ 100MB
- 协议识别准确率：≥ 95%

## 注意事项

1. **网络环境**: mDNS 基于多播，需要网络设备支持多播转发
2. **防火墙**: 确保 UDP 5353 端口（mDNS）和 TCP 扫描端口未被阻止
3. **法律合规**: 仅在授权范围内使用，禁止未授权扫描
4. **IPv6 支持**: 需要操作系统和网络设备支持 IPv6 多播

## 开发计划

- [x] Phase 1: 核心框架（端口扫描、mDNS 查询、CLI）
- [x] Phase 2: 协议识别（HTTP/SMB/SSH/FTP）
- [x] Phase 3: 深度解析（AFP/TXT 记录/设备指纹）
- [x] Phase 4: 优化完善（输出格式化、错误处理）
- [ ] 后续优化：
  - [ ] 更多协议解析器（Telnet、MySQL、PostgreSQL 等）
  - [ ] 插件系统支持自定义协议
  - [ ] 扫描结果导出（CSV、Excel）
  - [ ] Web UI 界面
  - [ ] 分布式扫描支持

## 许可证

MIT License

## 免责声明

本工具仅供网络安全研究和授权测试使用。使用本工具进行扫描时，请确保：
1. 获得目标网络所有者的明确授权
2. 遵守当地法律法规
3. 不对目标网络造成损害或干扰

开发者不对使用本工具造成的任何直接或间接损失承担责任。
