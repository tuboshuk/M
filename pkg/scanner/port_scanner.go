package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortScanner 端口扫描器
type PortScanner struct {
	timeout     time.Duration
	concurrency int
	verbose     bool
}

// NewPortScanner 创建端口扫描器
func NewPortScanner(timeout time.Duration, concurrency int, verbose bool) *PortScanner {
	return &PortScanner{
		timeout:     timeout,
		concurrency: concurrency,
		verbose:     verbose,
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	IP       string
	OpenPorts []int
}

// Scan 扫描单个 IP 的端口
func (ps *PortScanner) Scan(ctx context.Context, ip string, ports []int) ([]int, error) {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, ps.concurrency)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			if ps.isPortOpen(ip, p) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()

				if ps.verbose {
					fmt.Printf("[+] %s:%d open\n", ip, p)
				}
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts, nil
}

// isPortOpen 检查端口是否开放
func (ps *PortScanner) isPortOpen(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// ScanRange 扫描网段
func (ps *PortScanner) ScanRange(ctx context.Context, cidr string, ports []int) ([]ScanResult, error) {
	ips, err := ps.parseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
	}

	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, ps.concurrency)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			openPorts, err := ps.Scan(ctx, targetIP, ports)
			if err != nil {
				if ps.verbose {
					fmt.Printf("[-] Error scanning %s: %v\n", targetIP, err)
				}
				return
			}

			if len(openPorts) > 0 {
				mu.Lock()
				results = append(results, ScanResult{
					IP:        targetIP,
					OpenPorts: openPorts,
				})
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results, nil
}

// parseCIDR 解析 CIDR 获取 IP 列表
func (ps *PortScanner) parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ps.incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// 移除网络地址和广播地址
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// incrementIP 递增 IP 地址
func (ps *PortScanner) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParsePorts 解析端口范围字符串
func ParsePorts(portSpec string) ([]int, error) {
	var ports []int
	parts := strings.Split(portSpec, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 范围
			ranges := strings.Split(part, "-")
			if len(ranges) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(ranges[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port start: %s", ranges[0])
			}

			end, err := strconv.Atoi(ranges[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port end: %s", ranges[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			// 单个端口
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}

			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}

			ports = append(ports, p)
		}
	}

	return ports, nil
}
