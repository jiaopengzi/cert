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
