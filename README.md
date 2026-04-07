# M - mDNS资产测绘CLI工具

## 项目背景

在网络安全和资产盘点领域，快速识别和映射网络中的设备是一项重要任务。传统的网络扫描工具往往无法识别基于mDNS（多播DNS）协议的设备，这些设备通常在局域网中使用mDNS进行服务发现和名称解析。

本项目旨在开发一个专门的CLI工具，用于扫描指定IP网段和端口范围，识别mDNS协议资产，并深度解析Banner信息，为网络管理员和安全人员提供更全面的网络资产视图。

## 项目架构

本项目采用分层架构设计，主要包含以下组件：

### 1. 命令行接口（CLI）
- **位置**：`cmd/mdns-mapper/main.go`
- **功能**：处理命令行参数，解析用户输入，调用核心扫描逻辑
- **依赖**：使用Cobra库构建命令行界面

### 2. 核心扫描模块
- **位置**：`internal/scanner/`
- **功能**：解析CIDR网段和端口范围，执行并发端口扫描
- **组件**：
  - `scanner.go`：实现端口扫描逻辑
  - `scanner_test.go`：扫描模块的单元测试

### 3. mDNS协议解析模块
- **位置**：`internal/mdns/`
- **功能**：发送mDNS查询，解析mDNS响应
- **组件**：
  - `mdns.go`：实现mDNS协议的查询和解析

### 4. Banner深度识别模块
- **位置**：`internal/banner/`
- **功能**：抓取和解析服务Banner信息，识别服务类型和版本
- **组件**：
  - `banner.go`：实现Banner抓取和协议检测

### 5. 输出模块
- **位置**：`internal/output/`
- **功能**：将扫描结果格式化为不同输出格式（YAML、JSON、表格）
- **组件**：
  - `output.go`：实现输出格式化逻辑

### 6. 公共库
- **位置**：`pkg/`
- **功能**：提供可重用的功能模块
- **组件**：
  - `models/`：数据模型定义
  - `mdns/`：mDNS协议相关功能
  - `banner/`：Banner抓取相关功能
  - `scanner/`：端口扫描相关功能
  - `parser/`：解析相关功能
  - `output/`：输出相关功能

## 技术栈

- **编程语言**：Go 1.20+
- **核心库**：
  - `github.com/spf13/cobra`：命令行界面构建
  - `github.com/miekg/dns`：DNS协议解析
- **并发模型**：Go协程和通道
- **网络协议**：TCP、UDP、mDNS

## 功能特性

- **多网段扫描**：支持同时扫描多个IP网段
- **灵活的端口范围**：支持单个端口、端口范围和逗号分隔的端口列表
- **并发扫描**：可配置的并发数，提高扫描效率
- **mDNS协议识别**：专门识别基于mDNS协议的设备和服务
- **深度Banner识别**：识别服务类型、版本和详细信息
- **多种输出格式**：支持YAML、JSON和表格格式输出
- **详细的错误处理**：提供清晰的错误提示和日志

## 安装与使用

### 安装

```bash
go install github.com/tuboshuk/M/cmd/mdns-mapper@latest
```

### 基本使用

```bash
# 扫描单个网段和端口
mdns-mapper --cidr 192.168.1.0/24 --ports 5353

# 扫描多个网段和多个端口
mdns-mapper --cidr 192.168.1.0/24,192.168.2.0/24 --ports 5353,80,445

# 扫描端口范围
mdns-mapper --cidr 192.168.1.0/24 --ports 1-1000

# 自定义并发数和超时时间
mdns-mapper --cidr 192.168.1.0/24 --ports 5353 --concurrency 100 --timeout 5s

# 指定输出格式
mdns-mapper --cidr 192.168.1.0/24 --ports 5353 --output json
```

## 输出示例

```yaml
services:
  9/tcp workstation:
    Name: slw-nas [24:5e:be:69:a3:13]
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
    Hostname: slw-nas.local
    TTL: 10
  5000/tcp http:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
    Hostname: slw-nas.local
    TTL: 10
    path: /
  445/tcp smb:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
    Hostname: slw-nas.local
    TTL: 10
  5000/tcp qdiscover:
    Name: slw-nas
    IPv4: x.x.x.x
    IPv6: fe80::265e:beff:fe69:a313
    Hostname: slw-nas.local
    TTL: 10
    accessType: https
    accessPort: 86
    model: TS-X64
    displayModel: TS-464C
    fwVer: 5.2.9
    fwBuildNum: 20260214
device-info:
  Name: slw-nas(AFP)
  IPv4: x.x.x.x
  IPv6: fe80::265e:beff:fe69:a313
  Hostname: slw-nas.local
  TTL: 10
  model: Xserve
548/tcp afpovertcp:
  Name: slw-nas(AFP)
  IPv4: x.x.x.x
  IPv6: fe80::265e:beff:fe69:a313
  Hostname: slw-nas.local
  TTL: 10
answers:
  PTR:
    - _workstation._tcp.local
    - _http._tcp.local
    - _smb._tcp.local
    - _qdiscover._tcp.local
    - _device-info._tcp.local
    - _afpovertcp._tcp.local
```

## 项目状态

- **当前版本**：v1.0.0
- **开发状态**：活跃开发中
- **许可证**：MIT License
- **开源地址**：https://github.com/tuboshuk/M

## 贡献指南

欢迎提交Issue和Pull Request来改进这个项目。请确保：

1. 遵循Go代码风格
2. 为新功能添加测试
3. 提供清晰的提交信息
4. 确保代码通过所有测试

## 许可证

本项目采用MIT许可证，详见LICENSE文件。