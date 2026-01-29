//
// FilePath    : cert\core\validate_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书验证功能单元测试
//

package core

import (
	"net"
	"testing"
	"time"
)

// ============================================
// 证书验证测试
// ============================================

// TestValidateCert_Valid 测试验证有效证书.
func TestValidateCert_Valid(t *testing.T) {
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
		Subject:      Subject{CommonName: "api.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"api.example.com", "*.example.com"},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证证书.
	validateCfg := &CertValidateConfig{
		Cert:    serverCfg.Cert,
		CACert:  caCfg.Cert,
		DNSName: "api.example.com",
		Usage:   UsageServer,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证证书失败: %v", err)
	}
}

// TestValidateCert_WildcardDNS 测试验证通配符 DNS 名称.
func TestValidateCert_WildcardDNS(t *testing.T) {
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
		Subject:      Subject{CommonName: "example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"*.example.com"},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证通配符子域名.
	validateCfg := &CertValidateConfig{
		Cert:    serverCfg.Cert,
		CACert:  caCfg.Cert,
		DNSName: "sub.example.com",
		Usage:   UsageServer,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证通配符 DNS 失败: %v", err)
	}
}

// TestValidateCert_InvalidDNS 测试验证不匹配的 DNS 名称.
func TestValidateCert_InvalidDNS(t *testing.T) {
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
		Subject:      Subject{CommonName: "api.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"api.example.com"},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证不匹配的 DNS 名称.
	validateCfg := &CertValidateConfig{
		Cert:    serverCfg.Cert,
		CACert:  caCfg.Cert,
		DNSName: "other.example.com",
		Usage:   UsageServer,
	}
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("应该返回错误: DNS 名称不匹配")
	}
}

// TestValidateCert_ServerUsage 测试验证服务器认证用途.
func TestValidateCert_ServerUsage(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	serverCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "server",
		Subject:      Subject{CommonName: "server.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证服务器认证用途.
	validateCfg := &CertValidateConfig{
		Cert:  serverCfg.Cert,
		Usage: UsageServer,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证服务器认证用途失败: %v", err)
	}

	// 验证客户端认证用途应该失败.
	validateCfg.Usage = UsageClient
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("服务器证书不应该通过客户端认证验证")
	}
}

// TestValidateCert_ClientUsage 测试验证客户端认证用途.
func TestValidateCert_ClientUsage(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	clientCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "client",
		Subject:      Subject{CommonName: "client@example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageClient,
	}
	if err := GenerateCASignedCert(clientCfg); err != nil {
		t.Fatalf("生成客户端证书失败: %v", err)
	}

	// 验证客户端认证用途.
	validateCfg := &CertValidateConfig{
		Cert:  clientCfg.Cert,
		Usage: UsageClient,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证客户端认证用途失败: %v", err)
	}

	// 验证服务器认证用途应该失败.
	validateCfg.Usage = UsageServer
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("客户端证书不应该通过服务器认证验证")
	}
}

// TestValidateCert_ExpiredCert 测试验证过期证书.
func TestValidateCert_ExpiredCert(t *testing.T) {
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
		Subject:      Subject{CommonName: "server.example.com"},
		DaysValid:    1, // 只有 1 天有效期.
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 使用未来时间验证(证书已过期).
	validateCfg := &CertValidateConfig{
		Cert:      serverCfg.Cert,
		CheckTime: time.Now().AddDate(0, 0, 10), // 10 天后.
	}
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("应该返回错误: 证书已过期")
	}
}

// TestValidateCert_NotYetValid 测试验证尚未生效的证书.
func TestValidateCert_NotYetValid(t *testing.T) {
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
		Subject:      Subject{CommonName: "server.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 使用过去时间验证(证书尚未生效).
	// 注意: 证书的 NotBefore 是 time.Now().Add(-time.Hour), 所以需要更早的时间.
	validateCfg := &CertValidateConfig{
		Cert:      serverCfg.Cert,
		CheckTime: time.Now().AddDate(-1, 0, 0), // 1 年前.
	}
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("应该返回错误: 证书尚未生效")
	}
}

// TestValidateCert_CertChain 测试验证证书链.
func TestValidateCert_CertChain(t *testing.T) {
	// 生成根 CA.
	rootCACfg := &CACertConfig{
		DaysValid:    3650,
		Subject:      Subject{CommonName: "Root CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(rootCACfg); err != nil {
		t.Fatalf("生成根 CA 证书失败: %v", err)
	}

	// 生成中间 CA.
	intermediateCfg := &CASignedCertConfig{
		CACert:       rootCACfg.Cert,
		CAKey:        rootCACfg.Key,
		Name:         "intermediate-ca",
		Subject:      Subject{CommonName: "Intermediate CA"},
		DaysValid:    1825,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		IsCA:         true,
		MaxPathLen:   0,
	}
	if err := GenerateIntermediateCA(intermediateCfg); err != nil {
		t.Fatalf("生成中间 CA 证书失败: %v", err)
	}

	// 使用中间 CA 签发终端证书.
	leafCfg := &CASignedCertConfig{
		CACert:       intermediateCfg.Cert,
		CAKey:        intermediateCfg.Key,
		Name:         "leaf",
		Subject:      Subject{CommonName: "leaf.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"leaf.example.com"},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(leafCfg); err != nil {
		t.Fatalf("生成终端证书失败: %v", err)
	}

	// 验证证书链.
	validateCfg := &CertValidateConfig{
		Cert:            leafCfg.Cert,
		CACert:          rootCACfg.Cert,
		IntermediateCAs: []string{intermediateCfg.Cert},
		DNSName:         "leaf.example.com",
		Usage:           UsageServer,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证证书链失败: %v", err)
	}
}

// TestValidateCert_InvalidCert 测试验证无效证书.
func TestValidateCert_InvalidCert(t *testing.T) {
	validateCfg := &CertValidateConfig{
		Cert: "invalid cert",
	}
	err := ValidateCert(validateCfg)
	if err == nil {
		t.Error("应该返回错误: 无效的证书")
	}
}

// TestValidateCert_CodeSigningUsage 测试验证代码签名用途.
func TestValidateCert_CodeSigningUsage(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	codeCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "codesign",
		Subject:      Subject{CommonName: "Code Signing Cert"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageCodeSigning,
	}
	if err := GenerateCASignedCert(codeCfg); err != nil {
		t.Fatalf("生成代码签名证书失败: %v", err)
	}

	// 验证代码签名用途.
	validateCfg := &CertValidateConfig{
		Cert:  codeCfg.Cert,
		Usage: UsageCodeSigning,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证代码签名用途失败: %v", err)
	}
}

// TestValidateCert_EmailProtectionUsage 测试验证邮件保护用途.
func TestValidateCert_EmailProtectionUsage(t *testing.T) {
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
		Usage:        UsageEmailProtection,
	}
	if err := GenerateCASignedCert(emailCfg); err != nil {
		t.Fatalf("生成邮件保护证书失败: %v", err)
	}

	// 验证邮件保护用途.
	validateCfg := &CertValidateConfig{
		Cert:  emailCfg.Cert,
		Usage: UsageEmailProtection,
	}
	if err := ValidateCert(validateCfg); err != nil {
		t.Fatalf("验证邮件保护用途失败: %v", err)
	}
}

// ============================================
// IP 地址 SAN 测试
// ============================================

// TestValidateCert_IPAddress 测试 IP 地址 SAN.
func TestValidateCert_IPAddress(t *testing.T) {
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
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.100")},
		},
		Usage: UsageServer,
	}
	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证证书信息包含 IP 地址.
	info, err := GetCertInfo(serverCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	if len(info.IPAddresses) != 2 {
		t.Errorf("应该有 2 个 IP 地址, 实际有 %d 个", len(info.IPAddresses))
	}
}
