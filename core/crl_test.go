//
// FilePath    : cert\core\crl_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CRL 相关功能单元测试
//

package core

import (
	"testing"
)

// ============================================
// CRL 生成测试
// ============================================

// TestGenerateCRL 测试生成 CRL.
func TestGenerateCRL(t *testing.T) {
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

	// 生成一个证书用于吊销.
	certCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "test",
		Subject:      Subject{CommonName: "test.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(certCfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	// 生成 CRL.
	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	if crlCfg.CRL == "" {
		t.Error("CRL 为空")
	}
	if len(crlCfg.RevokedSerials) != 1 {
		t.Errorf("应该有 1 个吊销证书, 实际有 %d 个", len(crlCfg.RevokedSerials))
	}
	if crlCfg.ThisUpdate.IsZero() {
		t.Error("ThisUpdate 应该被设置")
	}
	if crlCfg.NextUpdate.IsZero() {
		t.Error("NextUpdate 应该被设置")
	}
}

// TestGenerateCRL_Empty 测试生成空 CRL.
func TestGenerateCRL_Empty(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{},
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成空 CRL 失败: %v", err)
	}

	if crlCfg.CRL == "" {
		t.Error("CRL 为空")
	}
	if len(crlCfg.RevokedSerials) != 0 {
		t.Errorf("应该有 0 个吊销证书, 实际有 %d 个", len(crlCfg.RevokedSerials))
	}
}

// TestGenerateCRL_MultipleCerts 测试吊销多个证书.
func TestGenerateCRL_MultipleCerts(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成多个证书.
	var certs []string
	for i := 0; i < 3; i++ {
		certCfg := &CASignedCertConfig{
			CACert:       caCfg.Cert,
			CAKey:        caCfg.Key,
			Name:         "test",
			Subject:      Subject{CommonName: "test.example.com"},
			DaysValid:    365,
			KeyAlgorithm: KeyAlgorithmECDSA,
			ECDSACurve:   CurveP256,
			Usage:        UsageServer,
		}
		if err := GenerateCASignedCert(certCfg); err != nil {
			t.Fatalf("生成证书失败: %v", err)
		}
		certs = append(certs, certCfg.Cert)
	}

	// 生成 CRL.
	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: certs,
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	if len(crlCfg.RevokedSerials) != 3 {
		t.Errorf("应该有 3 个吊销证书, 实际有 %d 个", len(crlCfg.RevokedSerials))
	}
}

// TestGenerateCRL_InvalidDaysValid 测试无效的有效期.
func TestGenerateCRL_InvalidDaysValid(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	crlCfg := &CRLConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		DaysValid: 0,
	}

	err := GenerateCRL(crlCfg)
	if err == nil {
		t.Error("应该返回错误: days valid must be > 0")
	}
}

// ============================================
// CRL 解析测试
// ============================================

// TestParseCRL 测试解析 CRL.
func TestParseCRL(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	certCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "test",
		Subject:      Subject{CommonName: "test.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(certCfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	// 解析 CRL.
	revokedList, err := ParseCRL(crlCfg.CRL)
	if err != nil {
		t.Fatalf("解析 CRL 失败: %v", err)
	}

	if len(revokedList) != 1 {
		t.Errorf("应该有 1 个吊销证书, 实际有 %d 个", len(revokedList))
	}

	if revokedList[0].SerialNumber == nil {
		t.Error("序列号不应该为空")
	}
	if revokedList[0].RevocationTime.IsZero() {
		t.Error("吊销时间不应该为空")
	}
}

// TestParseCRL_Invalid 测试解析无效的 CRL.
func TestParseCRL_Invalid(t *testing.T) {
	_, err := ParseCRL("invalid crl")
	if err == nil {
		t.Error("应该返回错误: 无效的 CRL")
	}
}

// ============================================
// 证书吊销检查测试
// ============================================

// TestIsCertRevoked_Revoked 测试检查已吊销的证书.
func TestIsCertRevoked_Revoked(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	certCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "test",
		Subject:      Subject{CommonName: "test.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(certCfg); err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}

	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	// 检查证书是否被吊销.
	revoked, err := IsCertRevoked(certCfg.Cert, crlCfg.CRL)
	if err != nil {
		t.Fatalf("检查证书吊销状态失败: %v", err)
	}

	if !revoked {
		t.Error("证书应该被标记为已吊销")
	}
}

// TestIsCertRevoked_NotRevoked 测试检查未吊销的证书.
func TestIsCertRevoked_NotRevoked(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	// 生成两个证书.
	cert1Cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "test1",
		Subject:      Subject{CommonName: "test1.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(cert1Cfg); err != nil {
		t.Fatalf("生成证书1失败: %v", err)
	}

	cert2Cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "test2",
		Subject:      Subject{CommonName: "test2.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(cert2Cfg); err != nil {
		t.Fatalf("生成证书2失败: %v", err)
	}

	// 只吊销证书1.
	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{cert1Cfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	// 检查证书2是否被吊销.
	revoked, err := IsCertRevoked(cert2Cfg.Cert, crlCfg.CRL)
	if err != nil {
		t.Fatalf("检查证书吊销状态失败: %v", err)
	}

	if revoked {
		t.Error("证书2不应该被标记为已吊销")
	}
}

// TestIsCertRevoked_InvalidCert 测试检查无效证书.
func TestIsCertRevoked_InvalidCert(t *testing.T) {
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("生成 CA 证书失败: %v", err)
	}

	crlCfg := &CRLConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		DaysValid: 30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	_, err := IsCertRevoked("invalid cert", crlCfg.CRL)
	if err == nil {
		t.Error("应该返回错误: 无效的证书")
	}
}
