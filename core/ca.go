//
// FilePath    : cert\core\ca.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CA 证书生成及相关功能
//

package core

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GenCACert 根据配置生成自签名 CA 证书与私钥.
func GenCACert(cfg *CACertConfig) error {
	// 配置验证.
	if err := ValidateCACertConfig(cfg); err != nil {
		return err
	}

	// 生成 CA 私钥.
	priv, err := generatePrivateKey(cfg.KeyAlgorithm, cfg.RSAKeyBits, cfg.ECDSACurve)
	if err != nil {
		return fmt.Errorf("generate ca private key: %w", err)
	}

	// 编码私钥为 PEM 格式.
	keyPEM, err := marshalPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal ca private key: %w", err)
	}

	cfg.Key = string(keyPEM)

	// 生成证书序列号.
	serial, err := randSerial()
	if err != nil {
		return fmt.Errorf("generate ca serial: %w", err)
	}

	// 构建证书模板.
	subject := toPkixName(cfg.Subject)
	if subject.CommonName == "" {
		subject.CommonName = "ca"
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, cfg.DaysValid),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            cfg.MaxPathLen,
		MaxPathLenZero:        cfg.PathLenZero,
	}

	// 生成自签名证书.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return fmt.Errorf("create ca certificate: %w", err)
	}

	// 编码证书为 PEM 格式.
	caCertBytes := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCertificate), Bytes: derBytes})
	cfg.Cert = string(caCertBytes)

	return nil
}

// GenerateCASignedCert 根据配置生成由 CA 签发的证书与私钥.
func GenerateCASignedCert(cfg *CASignedCertConfig) error {
	// 配置验证.
	if err := ValidateCASignedCertConfig(cfg); err != nil {
		return err
	}

	// 读取 CA 证书与私钥.
	caCert, caKey, err := loadCert(cfg.CACert, cfg.CAKey)
	if err != nil {
		return err
	}

	// 生成实例私钥.
	priv, err := generatePrivateKey(cfg.KeyAlgorithm, cfg.RSAKeyBits, cfg.ECDSACurve)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	// 生成证书序列号.
	serial, err := randSerial()
	if err != nil {
		return err
	}

	subject := toPkixName(cfg.Subject)
	if subject.CommonName == "" {
		subject.CommonName = cfg.Name
	}

	// 如果未配置 SAN.DNSNames, 自动将 CommonName 添加到 DNSNames.
	// 这是因为 Go 1.15+ 不再使用 CommonName 进行主机名验证.
	dnsNames := cfg.SAN.DNSNames
	if len(dnsNames) == 0 && subject.CommonName != "" && !cfg.IsCA {
		dnsNames = []string{subject.CommonName}
	}

	template := x509.Certificate{
		SerialNumber:   serial,
		Subject:        subject,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().AddDate(0, 0, cfg.DaysValid),
		DNSNames:       dnsNames,
		IPAddresses:    cfg.SAN.IPAddresses,
		EmailAddresses: cfg.SAN.EmailAddrs,
	}

	// 设置密钥用途.
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature

	// 根据证书类型设置扩展用途.
	if cfg.IsCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = cfg.MaxPathLen

		if cfg.MaxPathLen == 0 {
			template.MaxPathLenZero = true
		}
	} else {
		template.ExtKeyUsage = buildExtKeyUsage(cfg.Usage)
	}

	// 使用 CA 签发证书.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, publicKey(priv), caKey)
	if err != nil {
		return err
	}

	// 写入证书与私钥.
	certBytes := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockCertificate), Bytes: derBytes})

	keyBytes, err := marshalPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	cfg.Cert = string(certBytes)
	cfg.Key = string(keyBytes)

	return nil
}

// GenerateIntermediateCA 生成由上级 CA 签发的中间 CA 证书与私钥.
func GenerateIntermediateCA(cfg *CASignedCertConfig) error {
	cfg.IsCA = true
	return GenerateCASignedCert(cfg)
}

// GetCertInfo 通过证书 PEM 字符串获取证书信息.
func GetCertInfo(certPEM string) (*CertInfo, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	info := &CertInfo{
		SerialNumber: cert.SerialNumber.String(),
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
		DNSNames:     cert.DNSNames,
		IPAddresses:  make([]string, len(cert.IPAddresses)),
	}

	for i, ip := range cert.IPAddresses {
		info.IPAddresses[i] = ip.String()
	}

	// 解析密钥算法.
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		info.KeyAlgorithm = string(KeyAlgorithmRSA)
	case x509.ECDSA:
		info.KeyAlgorithm = string(KeyAlgorithmECDSA)
	case x509.Ed25519:
		info.KeyAlgorithm = string(KeyAlgorithmEd25519)
	default:
		info.KeyAlgorithm = "Unknown"
	}

	// 解析扩展密钥用途.
	for _, u := range cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			info.ExtKeyUsages = append(info.ExtKeyUsages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			info.ExtKeyUsages = append(info.ExtKeyUsages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			info.ExtKeyUsages = append(info.ExtKeyUsages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			info.ExtKeyUsages = append(info.ExtKeyUsages, "EmailProtection")
		}
	}

	return info, nil
}

// BuildCertChain 根据配置构建证书链.
func BuildCertChain(cfg *CertChainConfig) error {
	var chain strings.Builder

	// 终端实体证书.
	if cfg.EndEntityCert != "" {
		chain.WriteString(strings.TrimSpace(cfg.EndEntityCert))
		chain.WriteString("\n")
	}

	// 中间 CA 证书(从低到高)
	for _, ca := range cfg.IntermediateCAs {
		chain.WriteString(strings.TrimSpace(ca))
		chain.WriteString("\n")
	}

	// 根 CA 证书(可选).
	if cfg.RootCA != "" {
		chain.WriteString(strings.TrimSpace(cfg.RootCA))
		chain.WriteString("\n")
	}

	cfg.FullChain = chain.String()

	return nil
}
