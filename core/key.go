//
// FilePath    : cert\core\key.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 私钥相关功能
//

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// generatePrivateKey 根据算法类型生成私钥.a
//   - algo: 密钥算法,支持 RSA, ECDSA, Ed25519
//   - bits: RSA 密钥长度(仅对 RSA 有效)
//   - curve: ECDSA 曲线类型(仅对 ECDSA 有效)
func generatePrivateKey(algo KeyAlgorithm, bits int, curve ECDSACurve) (crypto.Signer, error) {
	switch algo {
	case KeyAlgorithmRSA:
		return rsa.GenerateKey(rand.Reader, bits)
	case KeyAlgorithmECDSA:
		c := getECDSACurve(curve)
		return ecdsa.GenerateKey(c, rand.Reader)
	case KeyAlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// getECDSACurve 获取 ECDSA 曲线.
func getECDSACurve(curve ECDSACurve) elliptic.Curve {
	switch curve {
	case CurveP256:
		return elliptic.P256()
	case CurveP384:
		return elliptic.P384()
	case CurveP521:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

// marshalPrivateKey 将私钥编码为 PEM 格式(PKCS#8).
func marshalPrivateKey(key crypto.Signer) ([]byte, error) {
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockPrivateKey), Bytes: pkcs8Key}), nil
}

// publicKey 从私钥中提取公钥.
func publicKey(priv crypto.Signer) crypto.PublicKey {
	return priv.Public()
}

// ParsePrivateKey 解析 PEM 格式私钥(支持 PKCS#8, PKCS#1, SEC 1).
func ParsePrivateKey(keyStr string) (crypto.Signer, error) {
	keyBlock, _ := pem.Decode([]byte(keyStr))
	if keyBlock == nil {
		return nil, errors.New("failed to parse private key PEM")
	}

	switch keyBlock.Type {
	case string(PEMBlockPrivateKey):
		// PKCS#8 格式.
		keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}

		signer, ok := keyAny.(crypto.Signer)
		if !ok {
			return nil, errors.New("private key does not implement crypto.Signer")
		}

		return signer, nil

	case string(PEMBlockRSAPrivateKey):
		// PKCS#1 RSA 格式.
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 RSA private key: %w", err)
		}

		return key, nil

	case string(PEMBlockECPrivateKey):
		// SEC 1 EC 格式.
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}

		return key, nil

	default:
		// 尝试按顺序解析.
		if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
			if signer, ok := key.(crypto.Signer); ok {
				return signer, nil
			}
		}

		if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
			return key, nil
		}

		if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
			return key, nil
		}

		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}
}

// MarshalPrivateKeyToPKCS1 将 RSA 私钥编码为 PKCS#1 格式(兼容旧格式).
func MarshalPrivateKeyToPKCS1(keyStr string) (string, error) {
	key, err := ParsePrivateKey(keyStr)
	if err != nil {
		return "", err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("key is not RSA, PKCS#1 only supports RSA keys")
	}

	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockRSAPrivateKey), Bytes: pkcs1Bytes})

	return string(pkcs1PEM), nil
}

// MarshalECPrivateKeyToSEC1 将 ECDSA 私钥编码为 SEC 1 格式.
func MarshalECPrivateKeyToSEC1(keyStr string) (string, error) {
	key, err := ParsePrivateKey(keyStr)
	if err != nil {
		return "", err
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("key is not ECDSA, SEC 1 only supports ECDSA keys")
	}

	sec1Bytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return "", fmt.Errorf("marshal EC private key: %w", err)
	}

	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockECPrivateKey), Bytes: sec1Bytes})

	return string(sec1PEM), nil
}

// ExtractPublicKeyFromCert 从证书中提取公钥.
func ExtractPublicKeyFromCert(certStr string) (string, error) {
	certBlock, _ := pem.Decode([]byte(certStr))
	if certBlock == nil {
		return "", errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: string(PEMBlockPublicKey), Bytes: pubBytes})

	return string(pubPEM), nil
}

// loadCert 加载证书和私钥.
func loadCert(certStr, keyStr string) (*x509.Certificate, crypto.Signer, error) {
	// 解析证书.
	certBlock, _ := pem.Decode([]byte(certStr))
	if certBlock == nil {
		return nil, nil, errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	// 解析私钥(支持多种格式).
	key, err := ParsePrivateKey(keyStr)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// randSerial 生成随机证书序列号.
func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// toPkixName 将 Subject 转换为 pkix.Name.
func toPkixName(subject Subject) pkix.Name {
	return pkix.Name{
		Country:            pick(subject.Country),
		Province:           pick(subject.State),
		Locality:           pick(subject.Locality),
		Organization:       pick(subject.Organization),
		OrganizationalUnit: pick(subject.OrganizationalUnit),
		CommonName:         subject.CommonName,
	}
}

// pick 将非空字符串转换为单元素切片.
func pick(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	return []string{value}
}

// buildExtKeyUsage 根据用途配置构建扩展密钥用途列表.
func buildExtKeyUsage(usage CertUsage) []x509.ExtKeyUsage {
	var extUsages []x509.ExtKeyUsage

	if usage == 0 {
		// 默认同时支持服务器和客户端认证.
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	if usage&UsageServer != 0 {
		extUsages = append(extUsages, x509.ExtKeyUsageServerAuth)
	}

	if usage&UsageClient != 0 {
		extUsages = append(extUsages, x509.ExtKeyUsageClientAuth)
	}

	if usage&UsageCodeSigning != 0 {
		extUsages = append(extUsages, x509.ExtKeyUsageCodeSigning)
	}

	if usage&UsageEmailProtection != 0 {
		extUsages = append(extUsages, x509.ExtKeyUsageEmailProtection)
	}

	return extUsages
}

// buildKeyUsages 根据 CertUsage 构建 x509.ExtKeyUsage 列表(用于验证).
func buildKeyUsages(usage CertUsage) []x509.ExtKeyUsage {
	if usage == 0 {
		// 默认允许任何用途.
		return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	var usages []x509.ExtKeyUsage
	if usage&UsageServer != 0 {
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	}

	if usage&UsageClient != 0 {
		usages = append(usages, x509.ExtKeyUsageClientAuth)
	}

	if usage&UsageCodeSigning != 0 {
		usages = append(usages, x509.ExtKeyUsageCodeSigning)
	}

	if usage&UsageEmailProtection != 0 {
		usages = append(usages, x509.ExtKeyUsageEmailProtection)
	}

	return usages
}

// ParseCertificate 解析 PEM 格式证书.
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}
