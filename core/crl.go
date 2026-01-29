//
// FilePath    : cert\core\crl.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CRL 相关功能
//

package core

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// newCRLBuilder 创建新的 CRL 构建器.
func newCRLBuilder(cfg *CRLConfig) *crlBuilder {
	return &crlBuilder{
		cfg:       cfg,
		serialSet: make(map[string]bool),
		crlNumber: big.NewInt(1),
		now:       time.Now(),
	}
}

// mergeExistingCRL 合并现有 CRL 中的吊销记录.
func (b *crlBuilder) mergeExistingCRL() error {
	if b.cfg.ExistingCRL == "" {
		return nil
	}

	existingEntries, err := ParseCRL(b.cfg.ExistingCRL)
	if err != nil {
		return fmt.Errorf("parse existing CRL: %w", err)
	}

	// 计算剔除截止时间.
	var pruneBeforeTime time.Time
	if b.cfg.PruneAfterDays > 0 {
		pruneBeforeTime = b.now.AddDate(0, 0, -b.cfg.PruneAfterDays)
	}

	for _, entry := range existingEntries {
		b.addExistingEntry(entry, pruneBeforeTime)
	}

	// 解析现有 CRL 的序号并递增.
	b.updateCRLNumber()

	return nil
}

// addExistingEntry 添加现有 CRL 中的条目.
func (b *crlBuilder) addExistingEntry(entry RevokedCertInfo, pruneBeforeTime time.Time) {
	// 如果启用了剔除，检查吊销时间是否超过阈值.
	if b.cfg.PruneAfterDays > 0 && entry.RevocationTime.Before(pruneBeforeTime) {
		b.cfg.PrunedCount++

		return
	}

	serialKey := entry.SerialNumber.String()
	if b.serialSet[serialKey] {
		return
	}

	b.serialSet[serialKey] = true
	b.revokedCerts = append(b.revokedCerts, x509.RevocationListEntry{
		SerialNumber:   entry.SerialNumber,
		RevocationTime: entry.RevocationTime,
	})
	b.cfg.RevokedSerials = append(b.cfg.RevokedSerials, entry.SerialNumber)
}

// updateCRLNumber 更新 CRL 序号.
func (b *crlBuilder) updateCRLNumber() {
	crlBlock, _ := pem.Decode([]byte(b.cfg.ExistingCRL))
	if crlBlock == nil {
		return
	}

	existingCRL, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return
	}

	b.crlNumber = new(big.Int).Add(existingCRL.Number, big.NewInt(1))
}

// processNewRevocations 处理新的吊销证书.
func (b *crlBuilder) processNewRevocations() {
	for _, certPEM := range b.cfg.RevokedCerts {
		b.addNewRevocation(certPEM)
	}
}

// addNewRevocation 添加新的吊销证书.
func (b *crlBuilder) addNewRevocation(certPEM string) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return
	}

	// 如果启用了跳过过期证书，检查证书是否已过期.
	if b.cfg.SkipExpired && parsedCert.NotAfter.Before(b.now) {
		b.cfg.SkippedExpired++

		return
	}

	// 检查是否已存在（去重）.
	serialKey := parsedCert.SerialNumber.String()
	if b.serialSet[serialKey] {
		return
	}

	b.serialSet[serialKey] = true
	b.revokedCerts = append(b.revokedCerts, x509.RevocationListEntry{
		SerialNumber:   parsedCert.SerialNumber,
		RevocationTime: b.now,
	})
	b.cfg.RevokedSerials = append(b.cfg.RevokedSerials, parsedCert.SerialNumber)
}

// build 构建并签名 CRL.
func (b *crlBuilder) build(caCert *x509.Certificate, caKey crypto.Signer) error {
	b.cfg.ThisUpdate = b.now
	b.cfg.NextUpdate = b.now.AddDate(0, 0, b.cfg.DaysValid)

	crlTemplate := x509.RevocationList{
		RevokedCertificateEntries: b.revokedCerts,
		Number:                    b.crlNumber,
		ThisUpdate:                b.cfg.ThisUpdate,
		NextUpdate:                b.cfg.NextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	b.cfg.CRL = string(pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCRL), Bytes: crlDER}))

	return nil
}

// GenerateCRL 根据配置生成证书吊销列表(CRL).
func GenerateCRL(cfg *CRLConfig) error {
	if err := ValidateCRLConfig(cfg); err != nil {
		return err
	}

	caCert, caKey, err := loadCert(cfg.CACert, cfg.CAKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	builder := newCRLBuilder(cfg)

	if err := builder.mergeExistingCRL(); err != nil {
		return err
	}

	builder.processNewRevocations()

	return builder.build(caCert, caKey)
}

// ParseCRL 解析 CRL 并返回已吊销证书信息.
func ParseCRL(crlPEM string) ([]RevokedCertInfo, error) {
	// 解析 CRL.
	crlBlock, _ := pem.Decode([]byte(crlPEM))
	if crlBlock == nil {
		return nil, errors.New("failed to parse CRL PEM")
	}

	// 解析 CRL 内容.
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	var result []RevokedCertInfo

	// 收集已吊销证书信息.
	for _, entry := range crl.RevokedCertificateEntries {
		result = append(result, RevokedCertInfo{
			SerialNumber:   entry.SerialNumber,
			RevocationTime: entry.RevocationTime,
			Reason:         entry.ReasonCode,
		})
	}

	return result, nil
}

// IsCertRevoked 检查证书是否被吊销.
//   - certPEM: 待检查的证书 PEM 字符串.
//   - crlPEM: CRL PEM 字符串.
func IsCertRevoked(certPEM, crlPEM string) (bool, error) {
	// 解析证书.
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return false, errors.New("failed to parse certificate PEM")
	}

	// 解析证书内容.
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse certificate: %w", err)
	}

	// 解析 CRL.
	revokedCerts, err := ParseCRL(crlPEM)
	if err != nil {
		return false, err
	}

	// 检查证书序列号.
	for _, revoked := range revokedCerts {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}
