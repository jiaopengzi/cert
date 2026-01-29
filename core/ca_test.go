//
// FilePath    : cert\core\ca_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CA 证书生成及相关功能单元测试
//

package core

import (
	"net"
	"strings"
	"testing"
)

// ============================================
// CA 证书生成测试
// ============================================

// TestGenCACert_RSA 测试使用 RSA 算法生成 CA 证书.
func TestGenCACert_RSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test RSA CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}

	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成 RSA CA 证书失败: %v", err)
	}

	// 验证证书和私钥已生成.
	if cfg.Cert == "" {
		t.Error("证书为空")
	}
	if cfg.Key == "" {
		t.Error("私钥为空")
	}

	// 验证证书信息.
	info, err := GetCertInfo(cfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}
	if !info.IsCA {
		t.Error("证书应该是 CA 证书")
	}
	if info.KeyAlgorithm != string(KeyAlgorithmRSA) {
		t.Errorf("密钥算法应该是 RSA, 实际是 %s", info.KeyAlgorithm)
	}
}

// TestGenCACert_ECDSA 测试使用 ECDSA 算法生成 CA 证书.
func TestGenCACert_ECDSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test ECDSA CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}

	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成 ECDSA CA 证书失败: %v", err)
	}

	info, err := GetCertInfo(cfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}
	if info.KeyAlgorithm != string(KeyAlgorithmECDSA) {
		t.Errorf("密钥算法应该是 ECDSA, 实际是 %s", info.KeyAlgorithm)
	}
}

// TestGenCACert_Ed25519 测试使用 Ed25519 算法生成 CA 证书.
func TestGenCACert_Ed25519(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test Ed25519 CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}

	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成 Ed25519 CA 证书失败: %v", err)
	}

	info, err := GetCertInfo(cfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}
	if info.KeyAlgorithm != string(KeyAlgorithmEd25519) {
		t.Errorf("密钥算法应该是 Ed25519, 实际是 %s", info.KeyAlgorithm)
	}
}

// TestGenCACert_InvalidDaysValid 测试无效的有效期.
func TestGenCACert_InvalidDaysValid(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid: 0,
		Subject:   Subject{CommonName: "Test CA"},
	}

	err := GenCACert(cfg)
	if err == nil {
		t.Error("应该返回错误: days valid must be > 0")
	}
}

// TestGenCACert_WithSubject 测试带完整主题信息的 CA 证书.
func TestGenCACert_WithSubject(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid: 365,
		Subject: Subject{
			Country:            "CN",
			State:              "Sichuan",
			Locality:           "Chengdu",
			Organization:       "Test Org",
			OrganizationalUnit: "Test Unit",
			CommonName:         "Test CA",
		},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}

	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	info, err := GetCertInfo(cfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	// 验证主题信息包含预期内容.
	if !strings.Contains(info.Subject, "CN=Test CA") {
		t.Errorf("主题应该包含 CN=Test CA, 实际是 %s", info.Subject)
	}
}

// TestGenCACert_ECDSACurves 测试不同的 ECDSA 曲线.
func TestGenCACert_ECDSACurves(t *testing.T) {
	curves := []ECDSACurve{CurveP256, CurveP384, CurveP521}

	for _, curve := range curves {
		t.Run(string(curve), func(t *testing.T) {
			cfg := &CACertConfig{
				DaysValid:    365,
				Subject:      Subject{CommonName: "Test CA " + string(curve)},
				KeyAlgorithm: KeyAlgorithmECDSA,
				ECDSACurve:   curve,
			}

			if err := GenCACert(cfg); err != nil {
				t.Fatalf("生成 ECDSA %s CA 证书失败: %v", curve, err)
			}

			if cfg.Cert == "" || cfg.Key == "" {
				t.Error("证书或私钥为空")
			}
		})
	}
}

// ============================================
// 服务器/客户端证书生成测试
// ============================================

// TestGenerateCASignedCert_ServerCert 测试生成服务器证书.
func TestGenerateCASignedCert_ServerCert(t *testing.T) {
	// 先生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成服务器证书.
	serverCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "server",
		Subject:      Subject{CommonName: "api.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames:    []string{"api.example.com", "*.example.com", "localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.100")},
		},
		Usage: UsageServer,
	}

	if err := GenerateCASignedCert(serverCfg); err != nil {
		t.Fatalf("生成服务器证书失败: %v", err)
	}

	// 验证证书信息.
	info, err := GetCertInfo(serverCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	// 验证 SAN.
	if len(info.DNSNames) != 3 {
		t.Errorf("应该有 3 个 DNS 名称, 实际有 %d 个", len(info.DNSNames))
	}
	if len(info.IPAddresses) != 2 {
		t.Errorf("应该有 2 个 IP 地址, 实际有 %d 个", len(info.IPAddresses))
	}

	// 验证用途.
	found := false
	for _, u := range info.ExtKeyUsages {
		if u == "ServerAuth" {
			found = true
			break
		}
	}
	if !found {
		t.Error("证书应该包含 ServerAuth 用途")
	}
}

// TestGenerateCASignedCert_ClientCert 测试生成客户端证书.
func TestGenerateCASignedCert_ClientCert(t *testing.T) {
	// 先生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成客户端证书.
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

	// 验证证书信息.
	info, err := GetCertInfo(clientCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	// 验证用途.
	found := false
	for _, u := range info.ExtKeyUsages {
		if u == "ClientAuth" {
			found = true
			break
		}
	}
	if !found {
		t.Error("证书应该包含 ClientAuth 用途")
	}
}

// TestGenerateCASignedCert_InvalidDaysValid 测试无效的有效期.
func TestGenerateCASignedCert_InvalidDaysValid(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	cfg := &CASignedCertConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		Name:      "test",
		DaysValid: 0,
	}

	err := GenerateCASignedCert(cfg)
	if err == nil {
		t.Error("应该返回错误: days valid must be > 0")
	}
}

// TestGenerateCASignedCert_MissingName 测试缺少名称.
func TestGenerateCASignedCert_MissingName(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	cfg := &CASignedCertConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		Name:      "",
		DaysValid: 365,
	}

	err := GenerateCASignedCert(cfg)
	if err == nil {
		t.Error("应该返回错误: name is required")
	}
}

// TestGenerateCASignedCert_DualUsage 测试同时支持服务器和客户端认证.
func TestGenerateCASignedCert_DualUsage(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "dual",
		Subject:      Subject{CommonName: "dual.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer | UsageClient,
	}

	if err := GenerateCASignedCert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	info, err := GetCertInfo(cfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	// 验证包含两种用途.
	hasServer, hasClient := false, false
	for _, u := range info.ExtKeyUsages {
		if u == "ServerAuth" {
			hasServer = true
		}
		if u == "ClientAuth" {
			hasClient = true
		}
	}
	if !hasServer || !hasClient {
		t.Error("证书应该同时包含 ServerAuth 和 ClientAuth 用途")
	}
}

// ============================================
// 中间 CA 测试
// ============================================

// TestGenerateIntermediateCA 测试生成中间 CA.
func TestGenerateIntermediateCA(t *testing.T) {
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
		MaxPathLen:   0,
	}
	if err := GenerateIntermediateCA(intermediateCfg); err != nil {
		t.Fatalf("生成中间 CA 证书失败: %v", err)
	}

	// 验证是 CA 证书.
	info, err := GetCertInfo(intermediateCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	if !info.IsCA {
		t.Error("中间 CA 证书应该是 CA 证书")
	}
}

// ============================================
// 证书链构建测试
// ============================================

// TestBuildCertChain 测试构建证书链.
func TestBuildCertChain(t *testing.T) {
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
	}
	if err := GenerateIntermediateCA(intermediateCfg); err != nil {
		t.Fatalf("生成中间 CA 证书失败: %v", err)
	}

	// 生成终端证书.
	leafCfg := &CASignedCertConfig{
		CACert:       intermediateCfg.Cert,
		CAKey:        intermediateCfg.Key,
		Name:         "leaf",
		Subject:      Subject{CommonName: "leaf.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(leafCfg); err != nil {
		t.Fatalf("生成终端证书失败: %v", err)
	}

	// 构建证书链.
	chainCfg := &CertChainConfig{
		EndEntityCert:   leafCfg.Cert,
		IntermediateCAs: []string{intermediateCfg.Cert},
		RootCA:          rootCACfg.Cert,
	}
	if err := BuildCertChain(chainCfg); err != nil {
		t.Fatalf("构建证书链失败: %v", err)
	}

	if chainCfg.FullChain == "" {
		t.Error("证书链为空")
	}

	// 验证证书链包含所有证书.
	if len(chainCfg.FullChain) < len(leafCfg.Cert)+len(intermediateCfg.Cert)+len(rootCACfg.Cert) {
		t.Error("证书链长度不正确")
	}
}

// TestBuildCertChain_Empty 测试构建空证书链.
func TestBuildCertChain_Empty(t *testing.T) {
	chainCfg := &CertChainConfig{}
	if err := BuildCertChain(chainCfg); err != nil {
		t.Fatalf("构建空证书链失败: %v", err)
	}

	if chainCfg.FullChain != "" {
		t.Error("空证书链应该为空字符串")
	}
}
