package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mdns-mapper/internal/banner"
	"mdns-mapper/internal/mdns"
	"mdns-mapper/internal/output"
	"mdns-mapper/internal/parser"
	"mdns-mapper/internal/scanner"
)

// Config 存储命令行参数配置
type Config struct {
	CIDR        string
	Ports       string
	Timeout     string
	Concurrency int
	Output      string
	Verbose     bool
}

var config Config

func main() {
	rootCmd := &cobra.Command{
		Use:   "mdns-mapper",
		Short: "mDNS资产测绘命令行工具",
		Long:  `用于扫描指定IP网段和端口范围，识别mDNS协议资产并深度解析Banner信息`,
		Run:   run,
	}

	rootCmd.Flags().StringVar(&config.CIDR, "cidr", "", "IP网段（支持多个，逗号分隔）")
	rootCmd.Flags().StringVar(&config.Ports, "ports", "", "端口范围（如 1-1000,8080,9000）")
	rootCmd.Flags().StringVar(&config.Timeout, "timeout", "2s", "连接超时（默认 2s）")
	rootCmd.Flags().IntVar(&config.Concurrency, "concurrency", 50, "并发数（默认 50）")
	rootCmd.Flags().StringVar(&config.Output, "output", "yaml", "输出格式（yaml/json/table，默认 yaml）")
	rootCmd.Flags().BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	rootCmd.MarkFlagRequired("cidr")
	rootCmd.MarkFlagRequired("ports")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// 解析超时时间
	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		timeout = 2 * time.Second
	}

	if config.Verbose {
		fmt.Printf("扫描配置: CIDR=%s, Ports=%s, Timeout=%v, Concurrency=%d, Output=%s\n",
			config.CIDR, config.Ports, timeout, config.Concurrency, config.Output)
	}

	// 开始时间
	startTime := time.Now()

	// 1. 端口扫描
	scan := scanner.NewScanner(config.CIDR, config.Ports, timeout, config.Concurrency)
	scanResults, err := scan.Scan()
	if err != nil {
		fmt.Printf("端口扫描失败: %v\n", err)
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Printf("发现 %d 个开放端口\n", len(scanResults))
	}

	// 2. 处理扫描结果
	assets := make([]output.Asset, 0)
	ipMap := make(map[string]*output.Asset)

	for _, result := range scanResults {
		// 检查IP是否已存在
		asset, exists := ipMap[result.IP]
		if !exists {
			asset = &output.Asset{
				IP:       result.IP,
				Services: make([]output.Service, 0),
			}
			ipMap[result.IP] = asset
			assets = append(assets, *asset)
		}

		// 3. Banner抓取
		grabber := banner.NewGrabber(timeout)
		bannerInfo, err := grabber.Grab(result.IP, result.Port)
		if err != nil {
			if config.Verbose {
				fmt.Printf("无法抓取 %s:%d 的Banner: %v\n", result.IP, result.Port, err)
			}
			continue
		}

		// 4. 协议解析
		protocolParser := parser.NewParser(bannerInfo.Protocol)
		parsedBanner := protocolParser.Parse(bannerInfo.Raw)

		// 5. mDNS探测
		mdnsProbe := mdns.NewProbe(timeout)
		mdnsRecord, err := mdnsProbe.Discover(result.IP)
		if err == nil {
			// 提取mDNS信息
			if len(mdnsRecord.A) > 0 {
				asset.IP = mdnsRecord.A[0].String()
			}
			// 提取主机名（从PTR记录）
			for _, ptr := range mdnsRecord.PTR {
				if !strings.Contains(ptr, "_services._dns-sd._udp.local") {
					// 提取主机名部分
					parts := strings.Split(ptr, ".")
					if len(parts) > 2 {
						hostname := strings.Join(parts[:len(parts)-2], ".")
						if asset.Hostname == "" {
							asset.Hostname = hostname
						}
					}
				}
			}
			// 保存mDNS记录
			asset.MDNSRecords = output.MDNSRecords{
				PTR: mdnsRecord.PTR,
				TXT: mdnsRecord.TXT,
			}
		}

		// 6. 添加服务信息
		service := output.Service{
			Port:     result.Port,
			Protocol: bannerInfo.Protocol,
			Service:  getServiceName(bannerInfo.Protocol, result.Port),
			Banner:   parsedBanner,
		}
		asset.Services = append(asset.Services, service)
	}

	// 7. 生成扫描结果
	duration := time.Since(startTime)
	scanResult := output.Result{
		ScanInfo: output.ScanInfo{
			CIDR:      config.CIDR,
			Ports:     config.Ports,
			Timestamp: startTime.Format(time.RFC3339),
			Duration:  duration.String(),
		},
		Assets: assets,
	}

	// 8. 输出结果
	writer := output.NewWriter(config.Output)
	if err := writer.Write(scanResult); err != nil {
		fmt.Printf("输出结果失败: %v\n", err)
		os.Exit(1)
	}
}

// getServiceName 根据协议和端口获取服务名称
func getServiceName(protocol string, port int) string {
	switch protocol {
	case "http":
		return "http"
	case "https":
		return "https"
	case "smb":
		return "smb"
	case "ssh":
		return "ssh"
	case "ftp":
		return "ftp"
	case "afp":
		return "afp"
	case "rdp":
		return "rdp"
	case "smtp":
		return "smtp"
	case "pop3":
		return "pop3"
	case "imap":
		return "imap"
	default:
		// 根据端口判断
		switch port {
		case 9:
			return "workstation"
		case 5000:
			return "http"
		case 445:
			return "smb"
		case 548:
			return "afpovertcp"
		default:
			return "unknown"
		}
	}
}
