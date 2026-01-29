//
// FilePath    : cert\core\csr_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CSR 相关功能单元测试
//

package core

import (
	"strings"
	"testing"
)

// ============================================
// CSR 生成测试
// ============================================

// TestGenerateCSR_RSA 测试使用 RSA 算法生成 CSR.
func TestGenerateCSR_RSA(t *testing.T) {
	cfg := &CSRConfig{
		Subject:      Subject{CommonName: "csr.example.com"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		SAN: SANConfig{
			DNSNames: []string{"csr.example.com", "www.csr.example.com"},
		},
	}

	if err := GenerateCSR(cfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	if cfg.CSR == "" {
		t.Error("CSR 为空")
	}
	if cfg.Key == "" {
		t.Error("私钥为空")
	}

	// 验证 CSR 格式.
	if !strings.Contains(cfg.CSR, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Error("CSR 格式不正确")
	}
}

// TestGenerateCSR_ECDSA 测试使用 ECDSA 算法生成 CSR.
func TestGenerateCSR_ECDSA(t *testing.T) {
	cfg := &CSRConfig{
		Subject:      Subject{CommonName: "ecdsa.example.com"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP384,
		SAN: SANConfig{
			DNSNames: []string{"ecdsa.example.com"},
		},
	}

	if err := GenerateCSR(cfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	if cfg.CSR == "" || cfg.Key == "" {
		t.Error("CSR 或私钥为空")
	}
}

// TestGenerateCSR_Ed25519 测试使用 Ed25519 算法生成 CSR.
func TestGenerateCSR_Ed25519(t *testing.T) {
	cfg := &CSRConfig{
		Subject:      Subject{CommonName: "ed25519.example.com"},
		KeyAlgorithm: KeyAlgorithmEd25519,
		SAN: SANConfig{
			DNSNames: []string{"ed25519.example.com"},
		},
	}

	if err := GenerateCSR(cfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	if cfg.CSR == "" || cfg.Key == "" {
		t.Error("CSR 或私钥为空")
	}
}

// TestGenerateCSR_MissingKeyAlgorithm 测试缺少密钥算法时报错.
func TestGenerateCSR_MissingKeyAlgorithm(t *testing.T) {
	cfg := &CSRConfig{
		Subject: Subject{CommonName: "default.example.com"},
	}

	err := GenerateCSR(cfg)
	if err == nil {
		t.Error("应该返回错误: key algorithm is required")
	}
	if err != ErrKeyAlgorithmRequired {
		t.Errorf("错误类型不匹配: got %v, want %v", err, ErrKeyAlgorithmRequired)
	}
}

// ============================================
// CSR 签发测试
// ============================================

// TestSignCSR_ServerAuth 测试签发服务器认证 CSR.
func TestSignCSR_ServerAuth(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成 CSR.
	csrCfg := &CSRConfig{
		Subject:      Subject{CommonName: "server.example.com"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		SAN: SANConfig{
			DNSNames: []string{"server.example.com"},
		},
	}
	if err := GenerateCSR(csrCfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	// 签发 CSR.
	signCfg := &CSRSignConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		CSR:       csrCfg.CSR,
		DaysValid: 365,
		Usage:     UsageServer,
	}
	if err := SignCSR(signCfg); err != nil {
		t.Fatalf("签发 CSR 失败: %v", err)
	}

	if signCfg.Cert == "" {
		t.Error("签发的证书为空")
	}

	// 验证证书信息.
	info, err := GetCertInfo(signCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

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

// TestSignCSR_DualAuth 测试签发同时支持服务器和客户端认证的 CSR.
func TestSignCSR_DualAuth(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成 CSR.
	csrCfg := &CSRConfig{
		Subject:      Subject{CommonName: "dual.example.com"},
		KeyAlgorithm: KeyAlgorithmEd25519,
		SAN: SANConfig{
			DNSNames: []string{"dual.example.com"},
		},
	}
	if err := GenerateCSR(csrCfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	// 签发 CSR.
	signCfg := &CSRSignConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		CSR:       csrCfg.CSR,
		DaysValid: 365,
		Usage:     UsageServer | UsageClient,
	}
	if err := SignCSR(signCfg); err != nil {
		t.Fatalf("签发 CSR 失败: %v", err)
	}

	info, err := GetCertInfo(signCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

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

// TestSignCSR_InvalidDaysValid 测试无效的有效期.
func TestSignCSR_InvalidDaysValid(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	csrCfg := &CSRConfig{
		Subject:      Subject{CommonName: "test.example.com"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenerateCSR(csrCfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	signCfg := &CSRSignConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		CSR:       csrCfg.CSR,
		DaysValid: 0,
	}

	err := SignCSR(signCfg)
	if err == nil {
		t.Error("应该返回错误: days valid must be > 0")
	}
}

// TestSignCSR_InvalidCSR 测试无效的 CSR.
func TestSignCSR_InvalidCSR(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	signCfg := &CSRSignConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		CSR:       "invalid csr",
		DaysValid: 365,
	}

	err := SignCSR(signCfg)
	if err == nil {
		t.Error("应该返回错误: 无效的 CSR")
	}
}

// TestSignCSR_AsCA 测试签发 CA 证书.
func TestSignCSR_AsCA(t *testing.T) {
	// 生成根 CA 证书.
	rootCACfg := &CACertConfig{
		DaysValid:    3650,
		Subject:      Subject{CommonName: "Root CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(rootCACfg); err != nil {
		t.Fatalf("生成根 CA 证书失败: %v", err)
	}

	// 生成中间 CA 的 CSR.
	csrCfg := &CSRConfig{
		Subject:      Subject{CommonName: "Intermediate CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenerateCSR(csrCfg); err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}

	// 签发为 CA 证书.
	signCfg := &CSRSignConfig{
		CACert:    rootCACfg.Cert,
		CAKey:     rootCACfg.Key,
		CSR:       csrCfg.CSR,
		DaysValid: 1825,
		IsCA:      true,
	}
	if err := SignCSR(signCfg); err != nil {
		t.Fatalf("签发 CSR 失败: %v", err)
	}

	info, err := GetCertInfo(signCfg.Cert)
	if err != nil {
		t.Fatalf("获取证书信息失败: %v", err)
	}

	if !info.IsCA {
		t.Error("证书应该是 CA 证书")
	}
}
