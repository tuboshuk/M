package models

import "time"

// ScanInfo 扫描任务信息
type ScanInfo struct {
	CIDR      string    `yaml:"cidr" json:"cidr"`
	Ports     string    `yaml:"ports" json:"ports"`
	Timestamp time.Time `yaml:"timestamp" json:"timestamp"`
	Duration  string    `yaml:"duration" json:"duration"`
}

// Asset 资产信息
type Asset struct {
	IP        string            `yaml:"ip" json:"ip"`
	MAC       string            `yaml:"mac,omitempty" json:"mac,omitempty"`
	Hostname  string            `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Services  []Service         `yaml:"services" json:"services"`
	MDNSRecs  MDNSRecords       `yaml:"mdns_records,omitempty" json:"mdns_records,omitempty"`
	ExtraInfo map[string]string `yaml:"extra_info,omitempty" json:"extra_info,omitempty"`
}

// Service 服务信息
type Service struct {
	Port     int           `yaml:"port" json:"port"`
	Protocol string        `yaml:"protocol" json:"protocol"`
	Service  string        `yaml:"service" json:"service"`
	Banner   ServiceBanner `yaml:"banner" json:"banner"`
}

// ServiceBanner 服务 Banner 信息
type ServiceBanner struct {
	Name        string            `yaml:"name,omitempty" json:"name,omitempty"`
	TTL         int               `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	Path        string            `yaml:"path,omitempty" json:"path,omitempty"`
	Server      string            `yaml:"server,omitempty" json:"server,omitempty"`
	Title       string            `yaml:"title,omitempty" json:"title,omitempty"`
	Domain      string            `yaml:"domain,omitempty" json:"domain,omitempty"`
	OS          string            `yaml:"os,omitempty" json:"os,omitempty"`
	Model       string            `yaml:"model,omitempty" json:"model,omitempty"`
	MachineType string            `yaml:"machine_type,omitempty" json:"machine_type,omitempty"`
	FWVer       string            `yaml:"fwVer,omitempty" json:"fwVer,omitempty"`
	AccessType  string            `yaml:"accessType,omitempty" json:"accessType,omitempty"`
	AccessPort  string            `yaml:"accessPort,omitempty" json:"accessPort,omitempty"`
	DisplayModel string           `yaml:"displayModel,omitempty" json:"displayModel,omitempty"`
	FWBuildNum  string            `yaml:"fwBuildNum,omitempty" json:"fwBuildNum,omitempty"`
	RawBanner   string            `yaml:"raw_banner,omitempty" json:"raw_banner,omitempty"`
	ExtraFields map[string]string `yaml:"extra_fields,omitempty" json:"extra_fields,omitempty"`
}

// MDNSRecords mDNS 记录
type MDNSRecords struct {
	PTR []string `yaml:"ptr,omitempty" json:"ptr,omitempty"`
	SRV []string `yaml:"srv,omitempty" json:"srv,omitempty"`
	TXT []string `yaml:"txt,omitempty" json:"txt,omitempty"`
	A   []string `yaml:"a,omitempty" json:"a,omitempty"`
	AAAA []string `yaml:"aaaa,omitempty" json:"aaaa,omitempty"`
}

// ScanResult 扫描结果
type ScanResult struct {
	ScanInfo ScanInfo `yaml:"scan_info" json:"scan_info"`
	Assets   []Asset  `yaml:"assets" json:"assets"`
}

// ScanConfig 扫描配置
type ScanConfig struct {
	CIDRs       []string
	Ports       []int
	PortRanges  string
	Timeout     time.Duration
	Concurrency int
	Verbose     bool
}
