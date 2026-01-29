//
// FilePath    : cert\core\key_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 私钥相关功能单元测试
//

package core

import (
	"strings"
	"testing"
)

// ============================================
// 私钥解析测试
// ============================================

// TestParsePrivateKey_PKCS8_RSA 测试解析 PKCS#8 RSA 私钥.
func TestParsePrivateKey_PKCS8_RSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	key, err := ParsePrivateKey(cfg.Key)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	if key == nil {
		t.Error("私钥不应该为空")
	}
}

// TestParsePrivateKey_PKCS8_ECDSA 测试解析 PKCS#8 ECDSA 私钥.
func TestParsePrivateKey_PKCS8_ECDSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	key, err := ParsePrivateKey(cfg.Key)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	if key == nil {
		t.Error("私钥不应该为空")
	}
}

// TestParsePrivateKey_PKCS8_Ed25519 测试解析 PKCS#8 Ed25519 私钥.
func TestParsePrivateKey_PKCS8_Ed25519(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	key, err := ParsePrivateKey(cfg.Key)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	if key == nil {
		t.Error("私钥不应该为空")
	}
}

// TestParsePrivateKey_PKCS1 测试解析 PKCS#1 RSA 私钥.
func TestParsePrivateKey_PKCS1(t *testing.T) {
	// 先生成 PKCS#8 格式的私钥.
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	// 转换为 PKCS#1 格式.
	pkcs1Key, err := MarshalPrivateKeyToPKCS1(cfg.Key)
	if err != nil {
		t.Fatalf("转换为 PKCS#1 失败: %v", err)
	}

	// 解析 PKCS#1 格式私钥.
	key, err := ParsePrivateKey(pkcs1Key)
	if err != nil {
		t.Fatalf("解析 PKCS#1 私钥失败: %v", err)
	}
	if key == nil {
		t.Error("私钥不应该为空")
	}
}

// TestParsePrivateKey_SEC1 测试解析 SEC 1 ECDSA 私钥.
func TestParsePrivateKey_SEC1(t *testing.T) {
	// 先生成 PKCS#8 格式的私钥.
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	// 转换为 SEC 1 格式.
	sec1Key, err := MarshalECPrivateKeyToSEC1(cfg.Key)
	if err != nil {
		t.Fatalf("转换为 SEC 1 失败: %v", err)
	}

	// 解析 SEC 1 格式私钥.
	key, err := ParsePrivateKey(sec1Key)
	if err != nil {
		t.Fatalf("解析 SEC 1 私钥失败: %v", err)
	}
	if key == nil {
		t.Error("私钥不应该为空")
	}
}

// TestParsePrivateKey_Invalid 测试解析无效私钥.
func TestParsePrivateKey_Invalid(t *testing.T) {
	_, err := ParsePrivateKey("invalid key")
	if err == nil {
		t.Error("应该返回错误: 无效的私钥")
	}
}

// ============================================
// 私钥格式转换测试
// ============================================

// TestMarshalPrivateKeyToPKCS1 测试转换为 PKCS#1 格式.
func TestMarshalPrivateKeyToPKCS1(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	pkcs1Key, err := MarshalPrivateKeyToPKCS1(cfg.Key)
	if err != nil {
		t.Fatalf("转换为 PKCS#1 失败: %v", err)
	}

	// 验证格式.
	if !strings.Contains(pkcs1Key, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("应该是 RSA PRIVATE KEY 格式")
	}
}

// TestMarshalPrivateKeyToPKCS1_NotRSA 测试转换非 RSA 私钥.
func TestMarshalPrivateKeyToPKCS1_NotRSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	_, err := MarshalPrivateKeyToPKCS1(cfg.Key)
	if err == nil {
		t.Error("应该返回错误: ECDSA 私钥不能转换为 PKCS#1")
	}
}

// TestMarshalECPrivateKeyToSEC1 测试转换为 SEC 1 格式.
func TestMarshalECPrivateKeyToSEC1(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	sec1Key, err := MarshalECPrivateKeyToSEC1(cfg.Key)
	if err != nil {
		t.Fatalf("转换为 SEC 1 失败: %v", err)
	}

	// 验证格式.
	if !strings.Contains(sec1Key, "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("应该是 EC PRIVATE KEY 格式")
	}
}

// TestMarshalECPrivateKeyToSEC1_NotECDSA 测试转换非 ECDSA 私钥.
func TestMarshalECPrivateKeyToSEC1_NotECDSA(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	_, err := MarshalECPrivateKeyToSEC1(cfg.Key)
	if err == nil {
		t.Error("应该返回错误: RSA 私钥不能转换为 SEC 1")
	}
}

// ============================================
// 公钥提取测试
// ============================================

// TestExtractPublicKeyFromCert 测试从证书提取公钥.
func TestExtractPublicKeyFromCert(t *testing.T) {
	cfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(cfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	pubKey, err := ExtractPublicKeyFromCert(cfg.Cert)
	if err != nil {
		t.Fatalf("提取公钥失败: %v", err)
	}

	if !strings.Contains(pubKey, "-----BEGIN PUBLIC KEY-----") {
		t.Error("应该是 PUBLIC KEY 格式")
	}
}

// TestExtractPublicKeyFromCert_Invalid 测试从无效证书提取公钥.
func TestExtractPublicKeyFromCert_Invalid(t *testing.T) {
	_, err := ExtractPublicKeyFromCert("invalid cert")
	if err == nil {
		t.Error("应该返回错误: 无效的证书")
	}
}
