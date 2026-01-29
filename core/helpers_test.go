//
// FilePath    : cert\core\helpers_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书便捷辅助函数单元测试
//

package core

import (
	"strings"
	"testing"
)

// TestEncryptWithCert_DecryptWithKey_RSA 测试 RSA 加密解密.
func TestEncryptWithCert_DecryptWithKey_RSA(t *testing.T) {
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

	// 生成 RSA 证书.
	rsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "rsa-test",
		Subject:      Subject{CommonName: "rsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(rsaCfg); err != nil {
		t.Fatalf("生成 RSA 证书失败: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for RSA encryption.")

	// 使用证书公钥加密.
	ciphertext, nonce, err := EncryptWithCert(rsaCfg.Cert, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("密文不应为空")
	}

	if len(nonce) == 0 {
		t.Error("nonce 不应为空")
	}

	// 使用私钥解密.
	decrypted, err := DecryptWithKey(rsaCfg.Cert, rsaCfg.Key, ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("解密后数据不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
	}
}

// TestEncryptWithCert_DecryptWithKey_ECDSA 测试 ECDSA 加密解密.
func TestEncryptWithCert_DecryptWithKey_ECDSA(t *testing.T) {
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

	// 生成 ECDSA 证书.
	ecdsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ecdsa-test",
		Subject:      Subject{CommonName: "ecdsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageClient,
	}
	if err := GenerateCASignedCert(ecdsaCfg); err != nil {
		t.Fatalf("生成 ECDSA 证书失败: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for ECDSA encryption.")

	// 使用证书公钥加密.
	ciphertext, nonce, err := EncryptWithCert(ecdsaCfg.Cert, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if len(nonce) == 0 {
		t.Error("nonce 不应为空")
	}

	// 使用私钥解密.
	decrypted, err := DecryptWithKey(ecdsaCfg.Cert, ecdsaCfg.Key, ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("解密后数据不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
	}
}

// TestEncryptWithCert_DecryptWithKey_Ed25519 测试 Ed25519 加密解密.
func TestEncryptWithCert_DecryptWithKey_Ed25519(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成 Ed25519 证书.
	ed25519Cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ed25519-test",
		Subject:      Subject{CommonName: "ed25519-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmEd25519,
		Usage:        UsageClient,
	}
	if err := GenerateCASignedCert(ed25519Cfg); err != nil {
		t.Fatalf("生成 Ed25519 证书失败: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for Ed25519 encryption.")

	// 使用证书公钥加密.
	ciphertext, nonce, err := EncryptWithCert(ed25519Cfg.Cert, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if len(nonce) == 0 {
		t.Error("nonce 不应为空")
	}

	// 使用私钥解密.
	decrypted, err := DecryptWithKey(ed25519Cfg.Cert, ed25519Cfg.Key, ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("解密后数据不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
	}
}

// TestEncryptWithCert_InvalidCert 测试无效证书.
func TestEncryptWithCert_InvalidCert(t *testing.T) {
	_, _, err := EncryptWithCert("invalid cert", []byte("test"))
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestDecryptWithKey_InvalidKey 测试无效私钥.
func TestDecryptWithKey_InvalidKey(t *testing.T) {
	// 生成有效证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	_, err := DecryptWithKey(caCfg.Cert, "invalid key", []byte{1, 2, 3})
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestSignData_VerifySignature_RSA 测试 RSA 签名验签.
func TestSignData_VerifySignature_RSA(t *testing.T) {
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

	// 生成 RSA 证书.
	rsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "rsa-test",
		Subject:      Subject{CommonName: "rsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(rsaCfg); err != nil {
		t.Fatalf("生成 RSA 证书失败: %v", err)
	}

	data := []byte("This is a test data for RSA signing.")

	// 签名.
	signature, err := SignData(rsaCfg.Key, data)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	if len(signature) == 0 {
		t.Error("签名不应为空")
	}

	// 验签.
	if err := VerifySignature(rsaCfg.Cert, data, signature); err != nil {
		t.Fatalf("验签失败: %v", err)
	}

	// 验证篡改数据应该失败.
	tamperedData := []byte("Tampered data")
	if err := VerifySignature(rsaCfg.Cert, tamperedData, signature); err == nil {
		t.Error("篡改数据验签应该失败")
	}
}

// TestSignData_VerifySignature_ECDSA 测试 ECDSA 签名验签.
func TestSignData_VerifySignature_ECDSA(t *testing.T) {
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

	// 生成 ECDSA 证书.
	ecdsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ecdsa-test",
		Subject:      Subject{CommonName: "ecdsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageClient,
	}
	if err := GenerateCASignedCert(ecdsaCfg); err != nil {
		t.Fatalf("生成 ECDSA 证书失败: %v", err)
	}

	data := []byte("This is a test data for ECDSA signing.")

	// 签名.
	signature, err := SignData(ecdsaCfg.Key, data)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 验签.
	if err := VerifySignature(ecdsaCfg.Cert, data, signature); err != nil {
		t.Fatalf("验签失败: %v", err)
	}
}

// TestSignData_VerifySignature_Ed25519 测试 Ed25519 签名验签.
func TestSignData_VerifySignature_Ed25519(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成 Ed25519 证书.
	ed25519Cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ed25519-test",
		Subject:      Subject{CommonName: "ed25519-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmEd25519,
		Usage:        UsageClient,
	}
	if err := GenerateCASignedCert(ed25519Cfg); err != nil {
		t.Fatalf("生成 Ed25519 证书失败: %v", err)
	}

	data := []byte("This is a test data for Ed25519 signing.")

	// 签名.
	signature, err := SignData(ed25519Cfg.Key, data)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 验签.
	if err := VerifySignature(ed25519Cfg.Cert, data, signature); err != nil {
		t.Fatalf("验签失败: %v", err)
	}
}

// TestSignData_InvalidKey 测试无效私钥.
func TestSignData_InvalidKey(t *testing.T) {
	_, err := SignData("invalid key", []byte("test"))
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestVerifySignature_InvalidCert 测试无效证书.
func TestVerifySignature_InvalidCert(t *testing.T) {
	err := VerifySignature("invalid cert", []byte("test"), []byte{1, 2, 3})
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestGetCertFingerprint_SHA256 测试 SHA256 指纹.
func TestGetCertFingerprint_SHA256(t *testing.T) {
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

	fingerprint, err := GetCertFingerprint(caCfg.Cert, HashAlgoSHA256)
	if err != nil {
		t.Fatalf("计算指纹失败: %v", err)
	}

	// 检查格式.
	if !strings.HasPrefix(fingerprint, "sha256:") {
		t.Errorf("指纹格式错误: %s", fingerprint)
	}

	// SHA256 哈希应该是 64 个十六进制字符.
	parts := strings.Split(fingerprint, ":")
	if len(parts) != 2 {
		t.Errorf("指纹格式错误: %s", fingerprint)
	}

	if len(parts[1]) != 64 {
		t.Errorf("SHA256 哈希长度错误: 期望 64, 实际 %d", len(parts[1]))
	}
}

// TestGetCertFingerprint_SHA384 测试 SHA384 指纹.
func TestGetCertFingerprint_SHA384(t *testing.T) {
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

	fingerprint, err := GetCertFingerprint(caCfg.Cert, HashAlgoSHA384)
	if err != nil {
		t.Fatalf("计算指纹失败: %v", err)
	}

	// 检查格式.
	if !strings.HasPrefix(fingerprint, "sha384:") {
		t.Errorf("指纹格式错误: %s", fingerprint)
	}

	// SHA384 哈希应该是 96 个十六进制字符.
	parts := strings.Split(fingerprint, ":")
	if len(parts[1]) != 96 {
		t.Errorf("SHA384 哈希长度错误: 期望 96, 实际 %d", len(parts[1]))
	}
}

// TestGetCertFingerprint_SHA512 测试 SHA512 指纹.
func TestGetCertFingerprint_SHA512(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	fingerprint, err := GetCertFingerprint(caCfg.Cert, HashAlgoSHA512)
	if err != nil {
		t.Fatalf("计算指纹失败: %v", err)
	}

	// 检查格式.
	if !strings.HasPrefix(fingerprint, "sha512:") {
		t.Errorf("指纹格式错误: %s", fingerprint)
	}

	// SHA512 哈希应该是 128 个十六进制字符.
	parts := strings.Split(fingerprint, ":")
	if len(parts[1]) != 128 {
		t.Errorf("SHA512 哈希长度错误: 期望 128, 实际 %d", len(parts[1]))
	}
}

// TestGetCertFingerprint_Consistent 测试指纹一致性.
func TestGetCertFingerprint_Consistent(t *testing.T) {
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

	// 多次计算应该得到相同结果.
	fingerprint1, _ := GetCertFingerprint(caCfg.Cert, HashAlgoSHA256)
	fingerprint2, _ := GetCertFingerprint(caCfg.Cert, HashAlgoSHA256)

	if fingerprint1 != fingerprint2 {
		t.Errorf("指纹不一致: %s != %s", fingerprint1, fingerprint2)
	}
}

// TestGetCertFingerprint_InvalidAlgo 测试无效算法.
func TestGetCertFingerprint_InvalidAlgo(t *testing.T) {
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

	_, err := GetCertFingerprint(caCfg.Cert, "md5")
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestGetCertFingerprint_InvalidCert 测试无效证书.
func TestGetCertFingerprint_InvalidCert(t *testing.T) {
	_, err := GetCertFingerprint("invalid cert", HashAlgoSHA256)
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestEncodeCertForHeader_DecodeCertFromHeader 测试编码解码.
func TestEncodeCertForHeader_DecodeCertFromHeader(t *testing.T) {
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

	// 编码.
	encoded := EncodeCertForHeader(caCfg.Cert)

	// Base64 编码后不应包含换行.
	if strings.Contains(encoded, "\n") {
		t.Error("Base64 编码不应包含换行")
	}

	// 解码.
	decoded, err := DecodeCertFromHeader(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if decoded != caCfg.Cert {
		t.Errorf("解码后数据不匹配")
	}
}

// TestDecodeCertFromHeader_InvalidBase64 测试无效 Base64.
func TestDecodeCertFromHeader_InvalidBase64(t *testing.T) {
	_, err := DecodeCertFromHeader("invalid base64!!!")
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestDecodeCertFromHeader_InvalidPEM 测试无效 PEM.
func TestDecodeCertFromHeader_InvalidPEM(t *testing.T) {
	// 有效 Base64 但无效 PEM.
	encoded := EncodeCertForHeader("not a valid PEM")
	_, err := DecodeCertFromHeader(encoded)
	if err == nil {
		t.Error("应该返回错误")
	}
}

// TestEncodeCertForHeader_ECDSA 测试 ECDSA 证书.
func TestEncodeCertForHeader_ECDSA(t *testing.T) {
	// 生成 ECDSA CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test ECDSA CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 编码解码.
	encoded := EncodeCertForHeader(caCfg.Cert)
	decoded, err := DecodeCertFromHeader(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if decoded != caCfg.Cert {
		t.Errorf("解码后数据不匹配")
	}
}

// TestEncodeCertForHeader_Ed25519 测试 Ed25519 证书.
func TestEncodeCertForHeader_Ed25519(t *testing.T) {
	// 生成 Ed25519 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test Ed25519 CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 编码解码.
	encoded := EncodeCertForHeader(caCfg.Cert)
	decoded, err := DecodeCertFromHeader(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if decoded != caCfg.Cert {
		t.Errorf("解码后数据不匹配")
	}
}
