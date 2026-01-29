//
// FilePath    : cert\core\csr.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CSR 相关功能
//

package core

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// GenerateCSR 生成证书签名请求(CSR).
func GenerateCSR(cfg *CSRConfig) error {
	// 配置验证.
	if err := ValidateCSRConfig(cfg); err != nil {
		return err
	}

	// 生成私钥.
	priv, err := generatePrivateKey(cfg.KeyAlgorithm, cfg.RSAKeyBits, cfg.ECDSACurve)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	// 构建主题信息.
	subject := toPkixName(cfg.Subject)

	// 如果未配置 SAN.DNSNames, 自动将 CommonName 添加到 DNSNames.
	dnsNames := cfg.SAN.DNSNames
	if len(dnsNames) == 0 && subject.CommonName != "" {
		dnsNames = []string{subject.CommonName}
	}

	// 构建 CSR 模板.
	template := x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dnsNames,
		IPAddresses:    cfg.SAN.IPAddresses,
		EmailAddresses: cfg.SAN.EmailAddrs,
	}

	// 生成 CSR.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return fmt.Errorf("create certificate request: %w", err)
	}

	// 编码为 PEM.
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCertificateRequest), Bytes: csrDER})

	keyPEM, err := marshalPrivateKey(priv)
	if err != nil {
		return err
	}

	cfg.CSR = string(csrPEM)
	cfg.Key = string(keyPEM)

	return nil
}

// SignCSR 使用 CA 签发 CSR.
func SignCSR(cfg *CSRSignConfig) error {
	// 配置验证.
	if err := ValidateCSRSignConfig(cfg); err != nil {
		return err
	}

	// 解析 CA 证书和私钥.
	caCert, caKey, err := loadCert(cfg.CACert, cfg.CAKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	// 解析 CSR.
	csrBlock, _ := pem.Decode([]byte(cfg.CSR))
	if csrBlock == nil {
		return errors.New("failed to parse CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	// 验证 CSR 签名.
	if sigErr := csr.CheckSignature(); sigErr != nil {
		return fmt.Errorf("CSR signature verification failed: %w", sigErr)
	}

	// 生成证书序列号.
	serial, err := randSerial()
	if err != nil {
		return err
	}

	// 如果 CSR 中未包含 DNSNames, 自动将 CommonName 添加到 DNSNames.
	dnsNames := csr.DNSNames
	if len(dnsNames) == 0 && csr.Subject.CommonName != "" && !cfg.IsCA {
		dnsNames = []string{csr.Subject.CommonName}
	}

	// 构建证书模板.
	template := x509.Certificate{
		SerialNumber:   serial,
		Subject:        csr.Subject,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().AddDate(0, 0, cfg.DaysValid),
		DNSNames:       dnsNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	// 根据证书类型设置扩展用途.
	if cfg.IsCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.ExtKeyUsage = buildExtKeyUsage(cfg.Usage)
	}

	// 签发证书.
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	cfg.Cert = string(pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCertificate), Bytes: certDER}))

	return nil
}
