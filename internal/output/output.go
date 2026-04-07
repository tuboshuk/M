package output

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// ScanInfo 扫描信息
type ScanInfo struct {
	CIDR      string `yaml:"cidr" json:"cidr"`
	Ports     string `yaml:"ports" json:"ports"`
	Timestamp string `yaml:"timestamp" json:"timestamp"`
	Duration  string `yaml:"duration" json:"duration"`
}

// Service 服务信息
type Service struct {
	Port     int               `yaml:"port" json:"port"`
	Protocol string            `yaml:"protocol" json:"protocol"`
	Service  string            `yaml:"service" json:"service"`
	Banner   map[string]string `yaml:"banner" json:"banner"`
}

// Asset 资产信息
type Asset struct {
	IP           string    `yaml:"ip" json:"ip"`
	MAC          string    `yaml:"mac,omitempty" json:"mac,omitempty"`
	Hostname     string    `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Services     []Service `yaml:"services" json:"services"`
	MDNSRecords  MDNSRecords `yaml:"mdns_records,omitempty" json:"mdns_records,omitempty"`
}

// MDNSRecords mDNS记录
type MDNSRecords struct {
	PTR []string `yaml:"ptr,omitempty" json:"ptr,omitempty"`
	TXT [][]string `yaml:"txt,omitempty" json:"txt,omitempty"`
}

// Result 扫描结果
type Result struct {
	ScanInfo ScanInfo `yaml:"scan_info" json:"scan_info"`
	Assets   []Asset  `yaml:"assets" json:"assets"`
}

// Writer 输出写入器接口
type Writer interface {
	Write(result Result) error
}

// NewWriter 根据格式创建输出写入器
func NewWriter(format string) Writer {
	switch format {
	case "json":
		return &JSONWriter{}
	case "table":
		return &TableWriter{}
	default:
		return &YAMLWriter{}
	}
}

// YAMLWriter YAML格式写入器
type YAMLWriter struct{}

// Write 写入YAML格式
func (w *YAMLWriter) Write(result Result) error {
	data, err := yaml.Marshal(result)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// JSONWriter JSON格式写入器
type JSONWriter struct{}

// Write 写入JSON格式
func (w *JSONWriter) Write(result Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// TableWriter 表格格式写入器
type TableWriter struct{}

// Write 写入表格格式
func (w *TableWriter) Write(result Result) error {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// 写入扫描信息
	fmt.Fprintln(writer, "=== 扫描信息 ===")
	fmt.Fprintf(writer, "CIDR\t%s\n", result.ScanInfo.CIDR)
	fmt.Fprintf(writer, "端口\t%s\n", result.ScanInfo.Ports)
	fmt.Fprintf(writer, "时间\t%s\n", result.ScanInfo.Timestamp)
	fmt.Fprintf(writer, "耗时\t%s\n\n", result.ScanInfo.Duration)

	// 写入资产信息
	fmt.Fprintln(writer, "=== 资产信息 ===")
	fmt.Fprintln(writer, "IP\tMAC\t主机名\t端口\t协议\t服务\tBanner信息")

	for _, asset := range result.Assets {
		for _, service := range asset.Services {
			bannerInfo := ""
			for k, v := range service.Banner {
				bannerInfo += fmt.Sprintf("%s=%s ", k, v)
			}
			fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
				asset.IP, asset.MAC, asset.Hostname, service.Port, service.Protocol, service.Service, bannerInfo)
		}
	}

	return writer.Flush()
}
