package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result 扫描结果
type Result struct {
	IP   string
	Port int
}

// Scanner 端口扫描器
type Scanner struct {
	CIDR        string
	Ports       string
	Timeout     time.Duration
	Concurrency int
}

// NewScanner 创建新的扫描器
func NewScanner(cidr, ports string, timeout time.Duration, concurrency int) *Scanner {
	return &Scanner{
		CIDR:        cidr,
		Ports:       ports,
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// Scan 执行端口扫描
func (s *Scanner) Scan() ([]Result, error) {
	// 解析CIDR网段
	ips, err := s.parseCIDR()
	if err != nil {
		return nil, err
	}

	// 解析端口范围
	ports, err := s.parsePorts()
	if err != nil {
		return nil, err
	}

	// 执行并发扫描
	results := s.concurrentScan(ips, ports)
	return results, nil
}

// parseCIDR 解析CIDR网段
func (s *Scanner) parseCIDR() ([]string, error) {
	var ips []string
	cidrs := strings.Split(s.CIDR, ",")

	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("无效的CIDR格式: %s", cidr)
		}

		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}

// incIP 递增IP地址
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parsePorts 解析端口范围
func (s *Scanner) parsePorts() ([]int, error) {
	var ports []int
	portRanges := strings.Split(s.Ports, ",")

	for _, portRange := range portRanges {
		portRange = strings.TrimSpace(portRange)
		if strings.Contains(portRange, "-") {
			// 处理端口范围
			parts := strings.Split(portRange, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", portRange)
			}

			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", parts[0])
			}

			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", parts[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("无效的端口范围: %s", portRange)
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(portRange)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", portRange)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("无效的端口号: %d", port)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// concurrentScan 并发扫描端口
func (s *Scanner) concurrentScan(ips []string, ports []int) []Result {
	results := make([]Result, 0, len(ips)*len(ports)/10) // 预分配容量，减少扩容
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 创建并发控制通道
	concurrency := s.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	// 限制最大并发数，避免系统资源耗尽
	if concurrency > 500 {
		concurrency = 500
	}
	limiter := make(chan struct{}, concurrency)

	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			limiter <- struct{}{}

			go func(ip string, port int) {
				defer wg.Done()
				defer func() {
					// 安全释放信号量
					select {
					case <-limiter:
					default:
					}
				}()

				// 增加错误处理
				defer func() {
					if r := recover(); r != nil {
						// 捕获并忽略panic，确保扫描继续
					}
				}()

				if s.isPortOpen(ip, port) {
					mu.Lock()
					results = append(results, Result{IP: ip, Port: port})
					mu.Unlock()
				}
			}(ip, port)
		}
	}

	wg.Wait()
	return results
}

// isPortOpen 检查端口是否开放
func (s *Scanner) isPortOpen(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
