package parser

import (
	"testing"

	"mdns-mapper/pkg/banner"
	"mdns-mapper/pkg/models"
)

func TestParseHTTP(t *testing.T) {
	parser := NewProtocolParser()

	grabResult := &banner.GrabResult{
		Protocol: "http",
		RawData:  "HTTP/1.1 200 OK\nServer: QNAP\n",
		Extra: map[string]string{
			"server": "QNAP",
			"title":  "NAS Login",
			"path":   "/",
		},
	}

	banner := parser.Parse("http", grabResult, nil)

	if banner.Server != "QNAP" {
		t.Errorf("Expected server QNAP, got %s", banner.Server)
	}

	if banner.Title != "NAS Login" {
		t.Errorf("Expected title NAS Login, got %s", banner.Title)
	}
}

func TestEnrichFromMDNS(t *testing.T) {
	parser := NewProtocolParser()

	mdnsData := map[string][]string{
		"txt": {
			"model=TS-X64",
			"fwVer=5.2.9",
			"accessType=https",
			"accessPort=86",
		},
	}

	banner := models.ServiceBanner{}
	banner = parser.enrichFromMDNS(banner, mdnsData)

	if banner.Model != "TS-X64" {
		t.Errorf("Expected model TS-X64, got %s", banner.Model)
	}

	if banner.FWVer != "5.2.9" {
		t.Errorf("Expected fwVer 5.2.9, got %s", banner.FWVer)
	}

	if banner.AccessType != "https" {
		t.Errorf("Expected accessType https, got %s", banner.AccessType)
	}
}

func TestExtractMAC(t *testing.T) {
	parser := NewProtocolParser()

	mdnsData := map[string][]string{
		"ptr": {"_http._tcp.local"},
		"txt": {"mac=24:5e:be:69:a3:13"},
	}

	mac := parser.ExtractMAC(mdnsData)
	expected := "24:5e:be:69:a3:13"

	if mac != expected {
		t.Errorf("Expected MAC %s, got %s", expected, mac)
	}
}
