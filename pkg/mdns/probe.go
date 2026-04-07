package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MDNSProbe mDNS 探测器
type MDNSProbe struct {
	ipv4Conn *net.UDPConn
	ipv6Conn *net.UDPConn
	timeout  time.Duration
	verbose  bool
}

// NewMDNSProbe 创建 mDNS 探测器
func NewMDNSProbe(timeout time.Duration, verbose bool) (*MDNSProbe, error) {
	probe := &MDNSProbe{
		timeout: timeout,
		verbose: verbose,
	}

	// 绑定 IPv4 多播地址
	ipv4Addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve IPv4 mDNS address: %w", err)
	}

	ipv4Conn, err := net.ListenMulticastUDP("udp4", nil, ipv4Addr)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Warning: Failed to bind IPv4 mDNS: %v\n", err)
		}
	} else {
		ipv4Conn.SetReadDeadline(time.Now().Add(timeout))
		probe.ipv4Conn = ipv4Conn
	}

	// 绑定 IPv6 多播地址
	ipv6Addr, err := net.ResolveUDPAddr("udp6", "[FF02::FB]:5353")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve IPv6 mDNS address: %w", err)
	}

	ipv6Conn, err := net.ListenMulticastUDP("udp6", nil, ipv6Addr)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Warning: Failed to bind IPv6 mDNS: %v\n", err)
		}
	} else {
		ipv6Conn.SetReadDeadline(time.Now().Add(timeout))
		probe.ipv6Conn = ipv6Conn
	}

	if probe.ipv4Conn == nil && probe.ipv6Conn == nil {
		return nil, fmt.Errorf("failed to bind both IPv4 and IPv6 mDNS")
	}

	return probe, nil
}

// Close 关闭连接
func (m *MDNSProbe) Close() {
	if m.ipv4Conn != nil {
		m.ipv4Conn.Close()
	}
	if m.ipv6Conn != nil {
		m.ipv6Conn.Close()
	}
}

// QueryServices 查询目标 IP 的 mDNS 服务
func (m *MDNSProbe) QueryServices(ctx context.Context, targetIP string) (map[string][]string, error) {
	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 查询所有服务类型
	serviceTypes := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_https._tcp.local",
		"_smb._tcp.local",
		"_afpovertcp._tcp.local",
		"_ssh._tcp.local",
		"_ftp._tcp.local",
		"_device-info._tcp.local",
		"_qdiscover._tcp.local",
	}

	for _, serviceType := range serviceTypes {
		wg.Add(1)
		go func(st string) {
			defer wg.Done()

			// PTR 查询
			ptrRecords, err := m.queryPTR(ctx, st)
			if err != nil {
				if m.verbose {
					fmt.Printf("[-] PTR query failed for %s: %v\n", st, err)
				}
				return
			}

			if len(ptrRecords) > 0 {
				mu.Lock()
				results["ptr"] = append(results["ptr"], ptrRecords...)
				mu.Unlock()
			}

			// SRV 查询
			srvRecords, err := m.querySRV(ctx, st)
			if err != nil {
				if m.verbose {
					fmt.Printf("[-] SRV query failed for %s: %v\n", st, err)
				}
				return
			}

			if len(srvRecords) > 0 {
				mu.Lock()
				results["srv"] = append(results["srv"], srvRecords...)
				mu.Unlock()
			}

			// TXT 查询
			txtRecords, err := m.queryTXT(ctx, st)
			if err != nil {
				if m.verbose {
					fmt.Printf("[-] TXT query failed for %s: %v\n", err)
				}
				return
			}

			if len(txtRecords) > 0 {
				mu.Lock()
				results["txt"] = append(results["txt"], txtRecords...)
				mu.Unlock()
			}
		}(serviceType)
	}

	// 等待所有查询完成或超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return results, nil
	case <-time.After(m.timeout * 2):
		return results, nil
	}
}

// queryPTR 发送 PTR 查询
func (m *MDNSProbe) queryPTR(ctx context.Context, serviceType string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(serviceType), dns.TypePTR)
	msg.RecursionDesired = false

	records, err := m.sendQuery(ctx, msg)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range records {
		if ptr, ok := ans.(*dns.PTR); ok {
			results = append(results, ptr.Ptr)
		}
	}

	return results, nil
}

// querySRV 发送 SRV 查询
func (m *MDNSProbe) querySRV(ctx context.Context, serviceType string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(serviceType), dns.TypeSRV)
	msg.RecursionDesired = false

	records, err := m.sendQuery(ctx, msg)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range records {
		if srv, ok := ans.(*dns.SRV); ok {
			record := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
			results = append(results, record)
		}
	}

	return results, nil
}

// queryTXT 发送 TXT 查询
func (m *MDNSProbe) queryTXT(ctx context.Context, serviceType string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(serviceType), dns.TypeTXT)
	msg.RecursionDesired = false

	records, err := m.sendQuery(ctx, msg)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range records {
		if txt, ok := ans.(*dns.TXT); ok {
			txtStr := strings.Join(txt.Txt, "")
			results = append(results, txtStr)
		}
	}

	return results, nil
}

// sendQuery 发送 DNS 查询
func (m *MDNSProbe) sendQuery(ctx context.Context, msg *dns.Msg) ([]dns.RR, error) {
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// 发送到 IPv4
	if m.ipv4Conn != nil {
		addr, _ := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
		m.ipv4Conn.SetWriteDeadline(time.Now().Add(m.timeout))
		_, err := m.ipv4Conn.WriteTo(buf, addr)
		if err == nil {
			records := m.readResponse()
			if len(records) > 0 {
				return records, nil
			}
		}
	}

	// 发送到 IPv6
	if m.ipv6Conn != nil {
		addr, _ := net.ResolveUDPAddr("udp6", "[FF02::FB]:5353")
		m.ipv6Conn.SetWriteDeadline(time.Now().Add(m.timeout))
		_, err := m.ipv6Conn.WriteTo(buf, addr)
		if err == nil {
			records := m.readResponse()
			if len(records) > 0 {
				return records, nil
			}
		}
	}

	return []dns.RR{}, nil
}

// readResponse 读取响应
func (m *MDNSProbe) readResponse() []dns.RR {
	var allRecords []dns.RR

	// 读取 IPv4 响应
	if m.ipv4Conn != nil {
		buf := make([]byte, 65536)
		m.ipv4Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := m.ipv4Conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:n]); err == nil {
				allRecords = append(allRecords, msg.Answer...)
			}
		}
	}

	// 读取 IPv6 响应
	if m.ipv6Conn != nil {
		buf := make([]byte, 65536)
		m.ipv6Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := m.ipv6Conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:n]); err == nil {
				allRecords = append(allRecords, msg.Answer...)
			}
		}
	}

	return allRecords
}

// QueryAllServices 查询所有可用服务（用于发现）
func (m *MDNSProbe) QueryAllServices(ctx context.Context) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("_services._dns-sd._udp.local"), dns.TypePTR)
	msg.RecursionDesired = false

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	var allServices []string

	// 发送到 IPv4
	if m.ipv4Conn != nil {
		addr, _ := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
		m.ipv4Conn.SetWriteDeadline(time.Now().Add(m.timeout))
		_, err := m.ipv4Conn.WriteTo(buf, addr)
		if err == nil {
			// 读取响应
			for i := 0; i < 5; i++ {
				buf := make([]byte, 65536)
				m.ipv4Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, _, err := m.ipv4Conn.ReadFromUDP(buf)
				if err == nil && n > 0 {
					msg := new(dns.Msg)
					if err := msg.Unpack(buf[:n]); err == nil {
						for _, ans := range msg.Answer {
							if ptr, ok := ans.(*dns.PTR); ok {
								allServices = append(allServices, ptr.Ptr)
							}
						}
					}
				}
			}
		}
	}

	return allServices, nil
}
