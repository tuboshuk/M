# mDNS Mapper 快速参考

## 编译
```bash
go build -o mdns-mapper.exe ./cmd
```

## 常用命令

### 基础扫描
```bash
# 扫描单个网段
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000

# 扫描常用端口
.\mdns-mapper.exe -c 192.168.1.0/24 -p 80,443,8080,5000
```

### 高级扫描
```bash
# 多网段 + 自定义并发 + JSON 输出
.\mdns-mapper.exe -c "192.168.1.0/24,192.168.2.0/24" \
                   -p 1-10000 \
                   -C 200 \
                   -o json \
                   -v

# 快速扫描（高并发）
.\mdns-mapper.exe -c 192.168.1.0/24 -p 1-1000 -C 500 -t 1s
```

### 输出格式
```bash
# YAML（默认，适合机器处理）
.\mdns-mapper.exe -c 192.168.1.0/24 -p 80 -o yaml

# JSON（适合程序解析）
.\mdns-mapper.exe -c 192.168.1.0/24 -p 80 -o json

# Table（适合人工阅读）
.\mdns-mapper.exe -c 192.168.1.0/24 -p 80 -o table
```

## 参数速查

| 参数 | 简写 | 说明 | 示例 |
|------|------|------|------|
| --cidr | -c | IP 网段 | 192.168.1.0/24 |
| --ports | -p | 端口范围 | 80,443,8000-8010 |
| --timeout | -t | 超时时间 | 2s, 500ms |
| --concurrency | -C | 并发数 | 50, 200 |
| --output | -o | 输出格式 | yaml, json, table |
| --verbose | -v | 详细模式 | (无参数) |

## 端口范围语法

```bash
# 单个端口
-p 80

# 多个端口
-p 80,443,8080

# 端口范围
-p 1-1000

# 混合使用
-p 80,443,8000-8010,9000
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
- _qdiscover._tcp.local

### Banner 深度解析
- HTTP: Server, Title, Path
- SMB: Domain, OS
- SSH: Version, Software
- FTP: Banner
- AFP: Model, Machine Type
- QNAP: Model, FWVer, BuildNum

## 输出示例字段

```yaml
assets:
  - ip: 192.168.1.100
    mac: 24:5e:be:69:a3:13
    hostname: slw-nas.local
    services:
      - port: 5000
        protocol: tcp
        service: http
        banner:
          name: slw-nas
          path: /
          server: QNAP
          title: NAS Login
          model: TS-X64
          fwVer: 5.2.9
    mdns_records:
      ptr:
        - _http._tcp.local
      txt:
        - model=TS-X64
        - fwVer=5.2.9
```

## 故障排查

### 无法绑定多播地址
```
[-] Warning: Failed to bind IPv4 mDNS: ...
```
**解决**: 检查防火墙设置，确保 UDP 5353 端口未被阻止

### 扫描结果为空
**可能原因**:
1. 目标网络没有 mDNS 服务
2. 网络设备不支持多播转发
3. 防火墙阻止了扫描

**解决**: 
- 使用 `-v` 参数查看详细输出
- 尝试减小并发数
- 增加超时时间

### 扫描速度慢
**优化**:
```bash
# 增加并发数
-C 200

# 减少超时时间
-t 1s

# 缩小端口范围
-p 80,443,8080
```

## 性能调优

| 场景 | 推荐配置 |
|------|---------|
| 快速发现 | -C 500 -t 1s -p 80,443,8080 |
| 全面扫描 | -C 100 -t 3s -p 1-10000 |
| 深度探测 | -C 50 -t 5s -p 1-65535 -v |
| 低干扰 | -C 20 -t 2s -p 1-1000 |

## 测试运行

```bash
# 运行单元测试
go test ./... -v

# 运行特定包测试
go test ./pkg/scanner -v
go test ./pkg/parser -v
```

## 项目文件

```
mdns-mapper/
├── cmd/main.go              # CLI 入口
├── pkg/
│   ├── scanner/             # 端口扫描
│   ├── mdns/                # mDNS 探测
│   ├── banner/              # Banner 抓取
│   ├── parser/              # 协议解析
│   ├── models/              # 数据模型
│   └── output/              # 输出格式化
├── README.md                # 使用说明
├── PROJECT_SUMMARY.md       # 项目总结
└── QUICK_REFERENCE.md       # 本文档
```

## 更多信息

- 完整文档：README.md
- 项目总结：PROJECT_SUMMARY.md
- PRD 文档：.trae/documents/mdns-cli-prd.md
