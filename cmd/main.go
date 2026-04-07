package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mdns-mapper/pkg/banner"
	"mdns-mapper/pkg/mdns"
	"mdns-mapper/pkg/models"
	"mdns-mapper/pkg/output"
	"mdns-mapper/pkg/parser"
	"mdns-mapper/pkg/scanner"

	"github.com/spf13/cobra"
)

var (
	cfgCIDR       string
	cfgPorts      string
	cfgTimeout    time.Duration
	cfgConcurrency int
	cfgOutput     string
	cfgVerbose    bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mdns-mapper",
		Short: "mDNS Asset Mapper - mDNS 协议资产测绘工具",
		Long: `mDNS Asset Mapper 是一个基于 Golang 的命令行工具，用于扫描和识别网络中的 mDNS 服务资产。

功能特性:
  - 扫描指定 IP 网段和端口范围
  - 识别 mDNS 服务并提取资产信息
  - 深度解析 Banner 信息（IP、端口、主机名、协议等）
  - 支持 YAML/JSON/Table 多种输出格式`,
		RunE: runScan,
	}

	rootCmd.Flags().StringVarP(&cfgCIDR, "cidr", "c", "", "IP 网段（支持多个，逗号分隔）")
	rootCmd.Flags().StringVarP(&cfgPorts, "ports", "p", "", "端口范围（如 1-1000,8080,9000）")
	rootCmd.Flags().DurationVarP(&cfgTimeout, "timeout", "t", 2*time.Second, "连接超时（默认 2s）")
	rootCmd.Flags().IntVarP(&cfgConcurrency, "concurrency", "C", 50, "并发数（默认 50）")
	rootCmd.Flags().StringVarP(&cfgOutput, "output", "o", "yaml", "输出格式（yaml/json/table）")
	rootCmd.Flags().BoolVarP(&cfgVerbose, "verbose", "v", false, "详细输出模式")

	rootCmd.MarkFlagRequired("cidr")
	rootCmd.MarkFlagRequired("ports")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// 创建上下文，支持 Ctrl+C 中断
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[*] Received interrupt signal, stopping...")
		cancel()
	}()

	startTime := time.Now()

	// 解析端口
	ports, err := scanner.ParsePorts(cfgPorts)
	if err != nil {
		return fmt.Errorf("failed to parse ports: %w", err)
	}

	if cfgVerbose {
		output.PrintProgress(os.Stdout, "Starting mDNS asset scan")
		output.PrintProgress(os.Stdout, "Target CIDR: %s", cfgCIDR)
		output.PrintProgress(os.Stdout, "Ports: %d ports in range", len(ports))
		output.PrintProgress(os.Stdout, "Timeout: %v, Concurrency: %d", cfgTimeout, cfgConcurrency)
	}

	// 创建扫描器
	portScanner := scanner.NewPortScanner(cfgTimeout, cfgConcurrency, cfgVerbose)

	// 解析 CIDR（支持多个）
	cidrs := splitCIDRs(cfgCIDR)
	var allScanResults []scanner.ScanResult

	for _, cidr := range cidrs {
		if cfgVerbose {
			output.PrintProgress(os.Stdout, "Scanning CIDR: %s", cidr)
		}

		results, err := portScanner.ScanRange(ctx, cidr, ports)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			output.PrintError(os.Stdout, "Failed to scan %s: %v", cidr, err)
			continue
		}

		allScanResults = append(allScanResults, results...)
	}

	if ctx.Err() != nil {
		return nil
	}

	if cfgVerbose {
		output.PrintProgress(os.Stdout, "Found %d hosts with open ports", len(allScanResults))
	}

	// 创建 mDNS 探测器
	mdnsProbe, err := mdns.NewMDNSProbe(cfgTimeout, cfgVerbose)
	if err != nil {
		output.PrintError(os.Stdout, "Failed to create mDNS probe: %v", err)
	}
	defer mdnsProbe.Close()

	// 创建 Banner 抓取器
	grabber := banner.NewGrabber(cfgTimeout, cfgVerbose)

	// 创建协议解析器
	parser := parser.NewProtocolParser()

	// 构建资产信息
	var assets []models.Asset
	for _, scanResult := range allScanResults {
		if ctx.Err() != nil {
			break
		}

		asset := models.Asset{
			IP:       scanResult.IP,
			Services: []models.Service{},
		}

		if cfgVerbose {
			output.PrintProgress(os.Stdout, "Probing %s", scanResult.IP)
		}

		// 查询 mDNS 服务
		mdnsData, err := mdnsProbe.QueryServices(ctx, scanResult.IP)
		if err != nil && cfgVerbose {
			output.PrintError(os.Stdout, "mDNS query failed for %s: %v", scanResult.IP, err)
		}

		// 填充 mDNS 记录
		if len(mdnsData) > 0 {
			asset.MDNSRecs.PTR = mdnsData["ptr"]
			asset.MDNSRecs.SRV = mdnsData["srv"]
			asset.MDNSRecs.TXT = mdnsData["txt"]
		}

		// 处理每个开放端口
		for _, port := range scanResult.OpenPorts {
			if ctx.Err() != nil {
				break
			}

			// 抓取 Banner
			grabResult, err := grabber.Grab(ctx, scanResult.IP, port)
			if err != nil && cfgVerbose {
				output.PrintError(os.Stdout, "Banner grab failed for %s:%d: %v", scanResult.IP, port, err)
			}

			// 确定服务类型
			serviceType := getServiceType(port, mdnsData)

			// 解析 Banner
			var serviceBanner models.ServiceBanner
			if grabResult != nil {
				serviceBanner = parser.Parse(serviceType, grabResult, mdnsData)
			} else {
				// 没有 Banner 数据，仅从 mDNS 解析
				serviceBanner = parser.Parse(serviceType, nil, mdnsData)
			}

			// 设置默认 TTL
			if serviceBanner.TTL == 0 {
				serviceBanner.TTL = 10
			}

			service := models.Service{
				Port:     port,
				Protocol: "tcp",
				Service:  serviceType,
				Banner:   serviceBanner,
			}

			asset.Services = append(asset.Services, service)
		}

		// 提取 MAC 地址
		if mac := parser.ExtractMAC(mdnsData); mac != "" {
			asset.MAC = mac
		}

		// 提取主机名
		if len(asset.MDNSRecs.PTR) > 0 {
			for _, ptr := range asset.MDNSRecs.PTR {
				if len(ptr) > 0 {
					parts := splitByDot(ptr)
					if len(parts) > 0 && parts[0] != "" {
						asset.Hostname = parts[0] + ".local"
						break
					}
				}
			}
		}

		if len(asset.Services) > 0 {
			assets = append(assets, asset)
		}
	}

	duration := time.Since(startTime)

	// 构建扫描结果
	result := models.ScanResult{
		ScanInfo: models.ScanInfo{
			CIDR:      cfgCIDR,
			Ports:     cfgPorts,
			Timestamp: startTime,
			Duration:  output.FormatDuration(int(duration.Seconds())),
		},
		Assets: assets,
	}

	// 输出结果
	var outputFormat output.OutputFormat
	switch cfgOutput {
	case "json":
		outputFormat = output.JSONFormat
	case "table":
		outputFormat = output.TableFormat
	default:
		outputFormat = output.YAMLFormat
	}

	outputter := output.NewOutputter(outputFormat, os.Stdout)
	return outputter.Output(result)
}

// splitCIDRs 分割多个 CIDR
func splitCIDRs(cidrStr string) []string {
	parts := splitByComma(cidrStr)
	var cidrs []string
	for _, p := range parts {
		p = trimSpace(p)
		if p != "" {
			cidrs = append(cidrs, p)
		}
	}
	return cidrs
}

// getServiceType 根据端口和 mDNS 数据确定服务类型
func getServiceType(port int, mdnsData map[string][]string) string {
	// 首先检查 mDNS PTR 记录
	if ptrRecords, ok := mdnsData["ptr"]; ok {
		for _, ptr := range ptrRecords {
			if containsPort(ptr, port) {
				return extractServiceName(ptr)
			}
		}
	}

	// 根据端口号推断
	switch port {
	case 80, 8080, 8000, 8008, 8888:
		return "http"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 548:
		return "afpovertcp"
	case 9:
		return "workstation"
	case 5000:
		return "http"
	default:
		return "unknown"
	}
}

// containsPort 检查 PTR 记录是否包含指定端口
func containsPort(ptr string, port int) bool {
	// 简化实现，实际应该解析 SRV 记录
	return false
}

// extractServiceName 从 PTR 记录提取服务名称
func extractServiceName(ptr string) string {
	// _http._tcp.local -> http
	if len(ptr) > 0 && ptr[0] == '_' {
		parts := splitByDot(ptr)
		if len(parts) > 0 {
			return trimUnderscore(parts[0])
		}
	}
	return "unknown"
}

// Helper functions to avoid strings package dependency issues
func splitByDot(s string) []string {
	var parts []string
	current := ""
	for _, r := range s {
		if r == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	parts = append(parts, current)
	return parts
}

func splitByComma(s string) []string {
	var parts []string
	current := ""
	for _, r := range s {
		if r == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	parts = append(parts, current)
	return parts
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func trimUnderscore(s string) string {
	if len(s) > 0 && s[0] == '_' {
		return s[1:]
	}
	return s
}
