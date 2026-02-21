//
// FilePath    : cert\core\validate.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书验证功能
//

package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// ValidateCert 验证证书的有效性.
func ValidateCert(cfg *CertValidateConfig) error {
	// 解析待验证证书.
	certBlock, _ := pem.Decode([]byte(cfg.Cert))
	if certBlock == nil {
		return errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// 验证时间.
	checkTime := cfg.CheckTime
	if checkTime.IsZero() {
		checkTime = time.Now()
	}

	if err := validateCertTime(cert, checkTime); err != nil {
		return err
	}

	// 验证用途.
	if cfg.Usage != 0 {
		if err := validateCertUsage(cert, cfg.Usage); err != nil {
			return err
		}
	}

	// 验证 DNS 名称.
	if cfg.DNSName != "" {
		if err := cert.VerifyHostname(cfg.DNSName); err != nil {
			return fmt.Errorf("hostname verification failed: %w", err)
		}
	}

	// 验证 CRL 吊销状态.
	if cfg.CRLData != "" {
		if err := validateCertCRL(cert, cfg.CRLData); err != nil {
			return err
		}
	}

	// 验证证书链.
	if cfg.CACert != "" {
		if err := validateCertChain(cert, cfg.CACert, cfg.IntermediateCAs, cfg.Usage); err != nil {
			return err
		}
	}

	return nil
}

// validateCertTime 验证证书时间有效性.
func validateCertTime(cert *x509.Certificate, checkTime time.Time) error {
	if checkTime.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid: valid from %s", cert.NotBefore.Format(time.RFC3339))
	}

	if checkTime.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired: valid until %s", cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// validateCertUsage 验证证书用途.
func validateCertUsage(cert *x509.Certificate, usage CertUsage) error {
	if usage&UsageServer != 0 {
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return errors.New("certificate is not valid for server authentication")
		}
	}

	if usage&UsageClient != 0 {
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
			return errors.New("certificate is not valid for client authentication")
		}
	}

	if usage&UsageCodeSigning != 0 {
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
			return errors.New("certificate is not valid for code signing")
		}
	}

	if usage&UsageEmailProtection != 0 {
		if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
			return errors.New("certificate is not valid for email protection")
		}
	}

	return nil
}

// validateCertCRL 从 CRL（证书吊销列表）检查证书是否已被吊销.
func validateCertCRL(cert *x509.Certificate, crlPEM string) error {
	revokedSerials, err := parseCRLRevokedSerials(crlPEM)
	if err != nil {
		return err
	}

	for _, serial := range revokedSerials {
		if cert.SerialNumber.Cmp(serial) == 0 {
			return fmt.Errorf("certificate serial number %s has been revoked", cert.SerialNumber.String())
		}
	}

	return nil
}

// parseCRLRevokedSerials 解析 CRL PEM 数据, 返回所有被吊销的证书序列号.
// 支持多个 CRL 块, 使用 x509.ParseRevocationList 解析, 并检查 CRL 是否已过期.
func parseCRLRevokedSerials(crlPEM string) ([]*big.Int, error) {
	var revokedSerials []*big.Int
	rest := []byte(crlPEM)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != string(PEMBlockCRL) {
			continue
		}

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CRL: %w", err)
		}

		// 检查 CRL 是否已过期.
		if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
			return nil, fmt.Errorf("CRL has expired: NextUpdate %s", crl.NextUpdate.Format(time.RFC3339))
		}

		for _, entry := range crl.RevokedCertificateEntries {
			revokedSerials = append(revokedSerials, entry.SerialNumber)
		}
	}

	if len(revokedSerials) == 0 {
		// 没有解析到任何 CRL 块时不视为错误, 等同于无吊销.
		return nil, nil
	}

	return revokedSerials, nil
}

// validateCertChain 验证证书链.
func validateCertChain(cert *x509.Certificate, caCertPEM string, intermediateCAs []string, usage CertUsage) error {
	// 构建根证书池.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caCertPEM)) {
		return errors.New("failed to parse root CA certificate")
	}

	// 构建中间证书池.
	intermediates := x509.NewCertPool()
	for _, caPEM := range intermediateCAs {
		if !intermediates.AppendCertsFromPEM([]byte(caPEM)) {
			return errors.New("failed to parse intermediate CA certificate")
		}
	}

	// 验证证书链.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     buildKeyUsages(usage),
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}
