package parser

import (
	"testing"
)

func TestHTTPParser_Parse(t *testing.T) {
	p := &HTTPParser{}
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><head><title>Test Page</title></head><body>Hello</body></html>"
	result := p.Parse(banner)
	if result["status"] != "200" {
		t.Errorf("Expected status 200, got %s", result["status"])
	}
	if _, ok := result["server"]; !ok {
		t.Error("Expected server field to exist")
	}
	if _, ok := result["title"]; !ok {
		t.Error("Expected title field to exist")
	}
}

func TestSSHParser_Parse(t *testing.T) {
	p := &SSHParser{}
	banner := "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
	result := p.Parse(banner)
	if result["version"] != "2.0" {
		t.Errorf("Expected version 2.0, got %s", result["version"])
	}
	if result["software"] != "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" {
		t.Errorf("Expected software OpenSSH_8.2p1 Ubuntu-4ubuntu0.5, got %s", result["software"])
	}
}

func TestFTPParser_Parse(t *testing.T) {
	p := &FTPParser{}
	banner := "220 ProFTPD 1.3.8 Server (ProFTPD) [192.168.1.1]"
	result := p.Parse(banner)
	if result["banner"] != "ProFTPD 1.3.8 Server (ProFTPD) [192.168.1.1]" {
		t.Errorf("Expected banner ProFTPD 1.3.8 Server (ProFTPD) [192.168.1.1], got %s", result["banner"])
	}
	if result["server"] != "ProFTPD" {
		t.Errorf("Expected server ProFTPD, got %s", result["server"])
	}
}
