# mDNS Asset Mapper

mDNS 资产测绘命令行工具 - 基于 Golang 开发的网络资产发现工具

## 功能特性

- ✅ 扫描指定 IP 网段和端口范围
- ✅ 识别 mDNS 服务并提取资产信息
- ✅ 深度解析 Banner 信息（IP、端口、主机名、协议等）
- ✅ 支持 YAML/JSON/Table 多种输出格式
- ✅ 高并发扫描，可配置并发度
- ✅ 支持 IPv4/IPv6 双栈 mDNS

## 快速开始

### 编译

```bash
go build -o mdns-mapper.exe ./cmd
```

### 基本用法

```bash
# 扫描单个网段
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000

# 扫描多个网段
.\mdns-mapper.exe -c "192.168.1.0/24,192.168.2.0/24" -p 80,443,8080

# 指定输出格式为 JSON
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000 -o json

# 使用表格格式输出
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000 -o table

# 增加并发数加快扫描
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-10000 -C 200

# 详细输出模式
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000 -v
```

### 参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| --cidr | -c | IP 网段（支持多个，逗号分隔） | 必填 |
| --ports | -p | 端口范围（如 1-1000,8080,9000） | 必填 |
| --timeout | -t | 连接超时（默认 2s） | 2s |
| --concurrency | -C | 并发数（默认 50） | 50 |
| --output | -o | 输出格式（yaml/json/table） | yaml |
| --verbose | -v | 详细输出模式 | false |

## 输出示例

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
      - port: 5000
        protocol: tcp
        service: http
        banner:
          name: slw-nas
          path: /
          server: QNAP
          title: NAS Login
      - port: 445
        protocol: tcp
        service: smb
        banner:
          name: slw-nas
          domain: WORKGROUP
          os: Unix
      - port: 548
        protocol: tcp
        service: afpovertcp
        banner:
          name: slw-nas(AFP)
          model: Xserve
          machine_type: TS-X64
    mdns_records:
      ptr:
        - _workstation._tcp.local
        - _http._tcp.local
        - _smb._tcp.local
        - _afpovertcp._tcp.local
      txt:
        - accessType=https
        - accessPort=86
        - model=TS-X64
        - fwVer=5.2.9
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
    5000/tcp http:
        Name=slw-nas
        path=/
        server=QNAP
        title=NAS Login
    445/tcp smb:
        Name=slw-nas
        domain=WORKGROUP
        os=Unix
    548/tcp afpovertcp:
        Name=slw-nas(AFP)
        model=Xserve
        machine_type=TS-X64
    answers:
      PTR:
        _workstation._tcp.local
        _http._tcp.local
        _smb._tcp.local
        _afpovertcp._tcp.local
```

## 支持的协议识别

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

## 项目结构

```
mdns-mapper/
├── cmd/                    # CLI 入口
│   └── main.go
├── pkg/
│   ├── banner/            # Banner 抓取模块
│   │   └── grabber.go
│   ├── mdns/              # mDNS 探测模块
│   │   └── probe.go
│   ├── models/            # 数据模型
│   │   └── models.go
│   ├── output/            # 输出格式化
│   │   └── output.go
│   ├── parser/            # 协议解析器
│   │   └── parser.go
│   └── scanner/           # 端口扫描器
│       └── port_scanner.go
├── go.mod
└── README.md
```

## 技术架构

```
用户输入 → CLI 参数解析 → 端口扫描 → mDNS 探测 → Banner 抓取 
                                      ↓
                                  协议识别
                                      ↓
                                  深度解析
                                      ↓
                                  结果聚合
                                      ↓
                                  格式化输出
```

## 依赖

- github.com/miekg/dns - DNS/mDNS 协议支持
- github.com/spf13/cobra - CLI 框架
- gopkg.in/yaml.v3 - YAML 输出

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
