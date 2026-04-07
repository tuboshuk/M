package mdns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Record mDNS记录
type Record struct {
	PTR []string
	SRV []dns.SRV
	TXT [][]string
	A   []net.IP
	AAAA []net.IP
}

// Probe mDNS探测器
type Probe struct {
	Timeout time.Duration
}

// NewProbe 创建新的mDNS探测器
func NewProbe(timeout time.Duration) *Probe {
	return &Probe{
		Timeout: timeout,
	}
}

// Discover 发现指定IP的mDNS服务
func (p *Probe) Discover(ip string) (*Record, error) {
	record := &Record{}

	// 发送PTR查询
	ptrRecords, err := p.queryPTR(ip)
	if err != nil {
		return nil, err
	}
	record.PTR = ptrRecords

	// 发送SRV、TXT、A、AAAA查询
	for _, ptr := range ptrRecords {
		srvRecords, err := p.querySRV(ip, ptr)
		if err == nil {
			record.SRV = append(record.SRV, srvRecords...)
		}

		txtRecords, err := p.queryTXT(ip, ptr)
		if err == nil {
			record.TXT = append(record.TXT, txtRecords...)
		}
	}

	// 发送A和AAAA查询
	aRecords, err := p.queryA(ip)
	if err == nil {
		record.A = aRecords
	}

	aaaaRecords, err := p.queryAAAA(ip)
	if err == nil {
		record.AAAA = aaaaRecords
	}

	return record, nil
}

// queryPTR 发送PTR查询
func (p *Probe) queryPTR(ip string) ([]string, error) {
	var records []string

	// 创建DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_services._dns-sd._udp.local"), dns.TypePTR)
	m.RecursionDesired = false

	// 发送查询
	response, err := p.sendQuery(ip, m)
	if err != nil {
		return nil, err
	}

	// 解析响应
	for _, ans := range response.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			records = append(records, ptr.Ptr)
		}
	}

	return records, nil
}

// querySRV 发送SRV查询
func (p *Probe) querySRV(ip, service string) ([]dns.SRV, error) {
	var records []dns.SRV

	// 创建DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(service), dns.TypeSRV)
	m.RecursionDesired = false

	// 发送查询
	response, err := p.sendQuery(ip, m)
	if err != nil {
		return nil, err
	}

	// 解析响应
	for _, ans := range response.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			records = append(records, *srv)
		}
	}

	return records, nil
}

// queryTXT 发送TXT查询
func (p *Probe) queryTXT(ip, service string) ([][]string, error) {
	var records [][]string

	// 创建DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(service), dns.TypeTXT)
	m.RecursionDesired = false

	// 发送查询
	response, err := p.sendQuery(ip, m)
	if err != nil {
		return nil, err
	}

	// 解析响应
	for _, ans := range response.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, txt.Txt)
		}
	}

	return records, nil
}

// queryA 发送A查询
func (p *Probe) queryA(ip string) ([]net.IP, error) {
	var records []net.IP

	// 创建DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ip+""), dns.TypeA)
	m.RecursionDesired = false

	// 发送查询
	response, err := p.sendQuery(ip, m)
	if err != nil {
		return nil, err
	}

	// 解析响应
	for _, ans := range response.Answer {
		if a, ok := ans.(*dns.A); ok {
			records = append(records, a.A)
		}
	}

	return records, nil
}

// queryAAAA 发送AAAA查询
func (p *Probe) queryAAAA(ip string) ([]net.IP, error) {
	var records []net.IP

	// 创建DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ip+""), dns.TypeAAAA)
	m.RecursionDesired = false

	// 发送查询
	response, err := p.sendQuery(ip, m)
	if err != nil {
		return nil, err
	}

	// 解析响应
	for _, ans := range response.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			records = append(records, aaaa.AAAA)
		}
	}

	return records, nil
}

// sendQuery 发送DNS查询
func (p *Probe) sendQuery(ip string, m *dns.Msg) (*dns.Msg, error) {
	// 创建UDP客户端
	client := &dns.Client{
		Timeout: p.Timeout,
	}

	// 发送查询到mDNS端口
	response, _, err := client.Exchange(m, fmt.Sprintf("%s:5353", ip))
	if err != nil {
		return nil, err
	}

	return response, nil
}
