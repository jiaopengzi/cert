//
// FilePath    : cert\core\utils_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书工具函数单元测试
//

package core

import (
	"net"
	"testing"
)

// ============================================
// 工具函数测试
// ============================================

// TestParseSANFromStr 测试从字符串解析 SAN.
func TestParseSANFromStr(t *testing.T) {
	san := ParseSANFromStr("a.com,b.com", "127.0.0.1,192.168.1.1")

	if len(san.DNSNames) != 2 {
		t.Errorf("期望 2 个 DNS 名称, 实际 %d 个", len(san.DNSNames))
	}
	if len(san.IPAddresses) != 2 {
		t.Errorf("期望 2 个 IP 地址, 实际 %d 个", len(san.IPAddresses))
	}
}

// TestParseSANFromStr_Empty 测试空输入.
func TestParseSANFromStr_Empty(t *testing.T) {
	san := ParseSANFromStr("", "")

	if len(san.DNSNames) != 0 {
		t.Errorf("期望 0 个 DNS 名称, 实际 %d 个", len(san.DNSNames))
	}
	if len(san.IPAddresses) != 0 {
		t.Errorf("期望 0 个 IP 地址, 实际 %d 个", len(san.IPAddresses))
	}
}

// ============================================
// SANConfig 测试
// ============================================

// TestSANConfig_DNSNames 测试 DNS 名称配置.
func TestSANConfig_DNSNames(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	serverCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "server",
		Subject:      Subject{CommonName: "server"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"api.example.com", "*.example.com", "localhost"},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	info, err := GetCertInfo(serverCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	if len(info.DNSNames) != 3 {
		t.Errorf("期望 3 个 DNS 名称, 实际 %d 个", len(info.DNSNames))
	}
}

// TestSANConfig_IPAddresses 测试 IP 地址配置.
func TestSANConfig_IPAddresses(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	serverCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "server",
		Subject:      Subject{CommonName: "server"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			IPAddresses: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("192.168.1.100"),
				net.ParseIP("::1"),
			},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	info, err := GetCertInfo(serverCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	if len(info.IPAddresses) != 3 {
		t.Errorf("期望 3 个 IP 地址, 实际 %d 个", len(info.IPAddresses))
	}
}

// TestSANConfig_EmailAddresses 测试电子邮件地址配置.
func TestSANConfig_EmailAddresses(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	emailCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "email",
		Subject:      Subject{CommonName: "user@example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			EmailAddrs: []string{"user@example.com", "admin@example.com"},
		},
		Usage: UsageEmailProtection,
	}
	if err := GenerateCASignedCert(emailCfg); err != nil {
		t.Fatalf("生成邮件证书失败: %v", err)
	}

	// 证书生成成功即可.
	if emailCfg.Cert == "" {
		t.Error("证书为空")
	}
}
