//
// FilePath    : cert\core\crl.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CRL 相关功能
//

package core

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateCRL 根据配置生成证书吊销列表(CRL).
func GenerateCRL(cfg *CRLConfig) error {
	// 配置验证.
	if err := ValidateCRLConfig(cfg); err != nil {
		return err
	}

	// 解析 CA 证书和私钥.
	caCert, caKey, err := loadCert(cfg.CACert, cfg.CAKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	// 收集要吊销的证书.
	var revokedCerts []x509.RevocationListEntry

	now := time.Now()

	// 通过序列号吊销证书.
	for _, certPEM := range cfg.RevokedCerts {
		// 解析证书 PEM.
		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			continue
		}

		// 解析证书.
		parsedCert, parseErr := x509.ParseCertificate(certBlock.Bytes)
		if parseErr != nil {
			continue
		}

		// 添加到吊销列表.
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   parsedCert.SerialNumber,
			RevocationTime: now,
		})

		// 添加到吊销序列号列表.
		cfg.RevokedSerials = append(cfg.RevokedSerials, parsedCert.SerialNumber)
	}

	// 构建 CRL 模板.
	cfg.ThisUpdate = now
	cfg.NextUpdate = now.AddDate(0, 0, cfg.DaysValid)

	crlTemplate := x509.RevocationList{
		RevokedCertificateEntries: revokedCerts,
		Number:                    big.NewInt(1),
		ThisUpdate:                cfg.ThisUpdate,
		NextUpdate:                cfg.NextUpdate,
	}

	// 生成 CRL.
	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	cfg.CRL = string(pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCRL), Bytes: crlDER}))

	return nil
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
