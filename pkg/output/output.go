package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"mdns-mapper/pkg/models"

	"gopkg.in/yaml.v3"
)

// OutputFormat 输出格式
type OutputFormat string

const (
	YAMLFormat  OutputFormat = "yaml"
	JSONFormat  OutputFormat = "json"
	TableFormat OutputFormat = "table"
)

// Outputter 输出器
type Outputter struct {
	format OutputFormat
	writer io.Writer
}

// NewOutputter 创建输出器
func NewOutputter(format OutputFormat, writer io.Writer) *Outputter {
	return &Outputter{
		format: format,
		writer: writer,
	}
}

// Output 输出扫描结果
func (o *Outputter) Output(result models.ScanResult) error {
	switch o.format {
	case YAMLFormat:
		return o.outputYAML(result)
	case JSONFormat:
		return o.outputJSON(result)
	case TableFormat:
		return o.outputTable(result)
	default:
		return o.outputYAML(result)
	}
}

// outputYAML 输出 YAML 格式
func (o *Outputter) outputYAML(result models.ScanResult) error {
	encoder := yaml.NewEncoder(o.writer)
	encoder.SetIndent(2)
	defer encoder.Close()

	return encoder.Encode(result)
}

// outputJSON 输出 JSON 格式
func (o *Outputter) outputJSON(result models.ScanResult) error {
	encoder := json.NewEncoder(o.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputTable 输出表格格式
func (o *Outputter) outputTable(result models.ScanResult) error {
	w := o.writer

	// 输出扫描信息
	fmt.Fprintln(w, "=== Scan Information ===")
	fmt.Fprintf(w, "CIDR:     %s\n", result.ScanInfo.CIDR)
	fmt.Fprintf(w, "Ports:    %s\n", result.ScanInfo.Ports)
	fmt.Fprintf(w, "Time:     %s\n", result.ScanInfo.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Duration: %s\n", result.ScanInfo.Duration)
	fmt.Fprintln(w)

	// 输出资产信息
	fmt.Fprintln(w, "=== Assets ===")
	for _, asset := range result.Assets {
		fmt.Fprintf(w, "\n[+] %s", asset.IP)
		if asset.MAC != "" {
			fmt.Fprintf(w, " [%s]", asset.MAC)
		}
		if asset.Hostname != "" {
			fmt.Fprintf(w, " (%s)", asset.Hostname)
		}
		fmt.Fprintln(w)

		// 输出服务
		for _, service := range asset.Services {
			fmt.Fprintf(w, "    %d/%s %s:\n", service.Port, service.Protocol, service.Service)
			
			// 输出 Banner 信息
			if service.Banner.Name != "" {
				fmt.Fprintf(w, "        Name=%s\n", service.Banner.Name)
			}
			if service.Banner.TTL > 0 {
				fmt.Fprintf(w, "        TTL=%d\n", service.Banner.TTL)
			}
			if service.Banner.Path != "" {
				fmt.Fprintf(w, "        path=%s\n", service.Banner.Path)
			}
			if service.Banner.Server != "" {
				fmt.Fprintf(w, "        server=%s\n", service.Banner.Server)
			}
			if service.Banner.Title != "" {
				fmt.Fprintf(w, "        title=%s\n", service.Banner.Title)
			}
			if service.Banner.Domain != "" {
				fmt.Fprintf(w, "        domain=%s\n", service.Banner.Domain)
			}
			if service.Banner.OS != "" {
				fmt.Fprintf(w, "        os=%s\n", service.Banner.OS)
			}
			if service.Banner.Model != "" {
				fmt.Fprintf(w, "        model=%s\n", service.Banner.Model)
			}
			if service.Banner.MachineType != "" {
				fmt.Fprintf(w, "        machine_type=%s\n", service.Banner.MachineType)
			}
			if service.Banner.FWVer != "" {
				fmt.Fprintf(w, "        fwVer=%s\n", service.Banner.FWVer)
			}
			if service.Banner.AccessType != "" {
				fmt.Fprintf(w, "        accessType=%s\n", service.Banner.AccessType)
			}
			if service.Banner.AccessPort != "" {
				fmt.Fprintf(w, "        accessPort=%s\n", service.Banner.AccessPort)
			}
			if service.Banner.DisplayModel != "" {
				fmt.Fprintf(w, "        displayModel=%s\n", service.Banner.DisplayModel)
			}
			if service.Banner.FWBuildNum != "" {
				fmt.Fprintf(w, "        fwBuildNum=%s\n", service.Banner.FWBuildNum)
			}
		}

		// 输出 mDNS 记录
		if len(asset.MDNSRecs.PTR) > 0 {
			fmt.Fprintln(w, "    answers:")
			fmt.Fprintln(w, "      PTR:")
			for _, ptr := range asset.MDNSRecs.PTR {
				fmt.Fprintf(w, "        %s\n", ptr)
			}
		}
	}

	return nil
}

// PrintProgress 打印进度信息
func PrintProgress(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "[*] "+format+"\n", args...)
}

// PrintError 打印错误信息
func PrintError(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "[-] "+format+"\n", args...)
}

// PrintSuccess 打印成功信息
func PrintSuccess(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "[+] "+format+"\n", args...)
}

// FormatDuration 格式化持续时间
func FormatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}

	minutes := seconds / 60
	secs := seconds % 60

	if secs == 0 {
		return fmt.Sprintf("%dm", minutes)
	}

	return fmt.Sprintf("%dm%ds", minutes, secs)
}

// CompactYAML 输出紧凑的 YAML 格式
func CompactYAML(result models.ScanResult) (string, error) {
	var builder strings.Builder
	encoder := yaml.NewEncoder(&builder)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(result); err != nil {
		return "", err
	}

	return builder.String(), nil
}
