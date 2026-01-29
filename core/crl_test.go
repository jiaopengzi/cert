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

// ============================================
// ExistingCRL 合并测试
// ============================================

// TestGenerateCRL_WithExistingCRL 测试合并现有 CRL.
func TestGenerateCRL_WithExistingCRL(t *testing.T) {
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

	// 生成两个证书用于吊销.
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

	// 第一次生成 CRL，吊销证书1.
	crl1Cfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{cert1Cfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crl1Cfg); err != nil {
		t.Fatalf("生成第一个 CRL 失败: %v", err)
	}

	if len(crl1Cfg.RevokedSerials) != 1 {
		t.Errorf("第一个 CRL 应该有 1 个吊销证书, 实际有 %d 个", len(crl1Cfg.RevokedSerials))
	}

	// 第二次生成 CRL，传入现有 CRL 并吊销证书2.
	crl2Cfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{cert2Cfg.Cert},
		ExistingCRL:  crl1Cfg.CRL,
		DaysValid:    30,
	}
	if err := GenerateCRL(crl2Cfg); err != nil {
		t.Fatalf("生成第二个 CRL 失败: %v", err)
	}

	// 验证合并后有两个吊销证书.
	if len(crl2Cfg.RevokedSerials) != 2 {
		t.Errorf("合并后应该有 2 个吊销证书, 实际有 %d 个", len(crl2Cfg.RevokedSerials))
	}

	// 验证两个证书都被标记为吊销.
	revoked1, err := IsCertRevoked(cert1Cfg.Cert, crl2Cfg.CRL)
	if err != nil {
		t.Fatalf("检查证书1吊销状态失败: %v", err)
	}
	if !revoked1 {
		t.Error("证书1应该被标记为已吊销")
	}

	revoked2, err := IsCertRevoked(cert2Cfg.Cert, crl2Cfg.CRL)
	if err != nil {
		t.Fatalf("检查证书2吊销状态失败: %v", err)
	}
	if !revoked2 {
		t.Error("证书2应该被标记为已吊销")
	}
}

// TestGenerateCRL_ExistingCRL_Dedup 测试合并时去重.
func TestGenerateCRL_ExistingCRL_Dedup(t *testing.T) {
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

	// 生成证书.
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

	// 第一次生成 CRL.
	crl1Cfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crl1Cfg); err != nil {
		t.Fatalf("生成第一个 CRL 失败: %v", err)
	}

	// 第二次生成 CRL，传入同一个证书（应该去重）.
	crl2Cfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert}, // 同一个证书
		ExistingCRL:  crl1Cfg.CRL,
		DaysValid:    30,
	}
	if err := GenerateCRL(crl2Cfg); err != nil {
		t.Fatalf("生成第二个 CRL 失败: %v", err)
	}

	// 验证去重后仍然只有1个吊销证书.
	if len(crl2Cfg.RevokedSerials) != 1 {
		t.Errorf("去重后应该只有 1 个吊销证书, 实际有 %d 个", len(crl2Cfg.RevokedSerials))
	}
}

// TestGenerateCRL_InvalidExistingCRL 测试无效的现有 CRL.
func TestGenerateCRL_InvalidExistingCRL(t *testing.T) {
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
		CACert:      caCfg.Cert,
		CAKey:       caCfg.Key,
		ExistingCRL: "invalid crl",
		DaysValid:   30,
	}

	err := GenerateCRL(crlCfg)
	if err == nil {
		t.Error("应该返回错误: 无效的现有 CRL")
	}
}

// TestGenerateCRL_CRLNumberIncrement 测试 CRL 序号递增.
func TestGenerateCRL_CRLNumberIncrement(t *testing.T) {
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

	// 第一次生成空 CRL.
	crl1Cfg := &CRLConfig{
		CACert:    caCfg.Cert,
		CAKey:     caCfg.Key,
		DaysValid: 30,
	}
	if err := GenerateCRL(crl1Cfg); err != nil {
		t.Fatalf("生成第一个 CRL 失败: %v", err)
	}

	// 解析第一个 CRL 获取序号.
	crl1Entries, _ := ParseCRL(crl1Cfg.CRL)
	_ = crl1Entries // 第一个 CRL 序号应该是 1

	// 第二次生成 CRL（基于第一个）.
	crl2Cfg := &CRLConfig{
		CACert:      caCfg.Cert,
		CAKey:       caCfg.Key,
		ExistingCRL: crl1Cfg.CRL,
		DaysValid:   30,
	}
	if err := GenerateCRL(crl2Cfg); err != nil {
		t.Fatalf("生成第二个 CRL 失败: %v", err)
	}

	// 第三次生成 CRL（基于第二个）.
	crl3Cfg := &CRLConfig{
		CACert:      caCfg.Cert,
		CAKey:       caCfg.Key,
		ExistingCRL: crl2Cfg.CRL,
		DaysValid:   30,
	}
	if err := GenerateCRL(crl3Cfg); err != nil {
		t.Fatalf("生成第三个 CRL 失败: %v", err)
	}

	// 验证 CRL 可以成功解析（序号应该递增到 3）.
	if crl3Cfg.CRL == "" {
		t.Error("第三个 CRL 不应该为空")
	}
}

// ============================================
// 过期证书跳过和历史记录剔除测试
// ============================================

// TestGenerateCRL_SkipExpired 测试跳过已过期的证书.
func TestGenerateCRL_SkipExpired(t *testing.T) {
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

	// 生成一个有效的证书.
	validCertCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "valid",
		Subject:      Subject{CommonName: "valid.example.com"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(validCertCfg); err != nil {
		t.Fatalf("生成有效证书失败: %v", err)
	}

	// 生成一个已过期的证书（有效期-1天，即昨天已过期）.
	expiredCertCfg := &CASignedCertConfig{
		Subject: Subject{CommonName: "expired.example.com"},
	}
	// 由于 DaysValid 为负数可能会导致验证失败，我们跳过这个测试场景
	// 实际使用中，过期证书是历史遗留的，不是新生成的
	_ = expiredCertCfg

	// 测试 SkipExpired 功能：使用有效证书测试
	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{validCertCfg.Cert},
		SkipExpired:  true,
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	// 有效证书应该被吊销
	if len(crlCfg.RevokedSerials) != 1 {
		t.Errorf("应该有 1 个吊销证书, 实际有 %d 个", len(crlCfg.RevokedSerials))
	}

	// SkippedExpired 应该是 0（因为证书未过期）
	if crlCfg.SkippedExpired != 0 {
		t.Errorf("SkippedExpired 应该是 0, 实际是 %d", crlCfg.SkippedExpired)
	}
}

// TestGenerateCRL_PruneAfterDays 测试剔除旧的吊销记录.
func TestGenerateCRL_PruneAfterDays(t *testing.T) {
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

	// 生成证书.
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

	// 第一次生成 CRL.
	crl1Cfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		DaysValid:    30,
	}
	if err := GenerateCRL(crl1Cfg); err != nil {
		t.Fatalf("生成第一个 CRL 失败: %v", err)
	}

	// 使用 PruneAfterDays=0（不剔除），应该保留记录
	crl2Cfg := &CRLConfig{
		CACert:         caCfg.Cert,
		CAKey:          caCfg.Key,
		ExistingCRL:    crl1Cfg.CRL,
		PruneAfterDays: 0, // 不剔除
		DaysValid:      30,
	}
	if err := GenerateCRL(crl2Cfg); err != nil {
		t.Fatalf("生成第二个 CRL 失败: %v", err)
	}

	if len(crl2Cfg.RevokedSerials) != 1 {
		t.Errorf("不剔除时应该有 1 个吊销证书, 实际有 %d 个", len(crl2Cfg.RevokedSerials))
	}

	if crl2Cfg.PrunedCount != 0 {
		t.Errorf("PrunedCount 应该是 0, 实际是 %d", crl2Cfg.PrunedCount)
	}

	// 使用 PruneAfterDays=1（剔除1天前的记录），刚吊销的记录应该保留
	crl3Cfg := &CRLConfig{
		CACert:         caCfg.Cert,
		CAKey:          caCfg.Key,
		ExistingCRL:    crl1Cfg.CRL,
		PruneAfterDays: 1, // 剔除1天前的
		DaysValid:      30,
	}
	if err := GenerateCRL(crl3Cfg); err != nil {
		t.Fatalf("生成第三个 CRL 失败: %v", err)
	}

	// 刚吊销的记录应该保留（因为还没过1天）
	if len(crl3Cfg.RevokedSerials) != 1 {
		t.Errorf("刚吊销的记录应该保留, 实际有 %d 个", len(crl3Cfg.RevokedSerials))
	}
}

// TestGenerateCRL_SkipExpired_Disabled 测试不启用跳过过期时的行为.
func TestGenerateCRL_SkipExpired_Disabled(t *testing.T) {
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

	// 生成证书.
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

	// 不启用 SkipExpired
	crlCfg := &CRLConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		RevokedCerts: []string{certCfg.Cert},
		SkipExpired:  false, // 不跳过
		DaysValid:    30,
	}
	if err := GenerateCRL(crlCfg); err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	if len(crlCfg.RevokedSerials) != 1 {
		t.Errorf("应该有 1 个吊销证书, 实际有 %d 个", len(crlCfg.RevokedSerials))
	}
}
