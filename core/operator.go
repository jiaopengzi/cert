//
// FilePath    : cert\core\operator.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书加密操作器定义
//

package core

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// Certificate 表示一个证书及其私钥的组合.
// 根据不同的密钥算法, 支持不同的加密和签名操作.
type Certificate struct {
	CertPEM      string            // 证书 PEM 格式
	KeyPEM       string            // 私钥 PEM 格式
	KeyAlgorithm KeyAlgorithm      // 密钥算法
	cert         *x509.Certificate // 解析后的证书
	privateKey   crypto.Signer     // 解析后的私钥
}

// CryptoOperator 定义证书加密操作接口.
// 不同类型的证书(RSA/ECDSA/Ed25519)实现此接口.
type CryptoOperator interface {
	// Sign 使用私钥对数据进行签名.
	Sign(data []byte) ([]byte, error)

	// Verify 使用证书公钥验证签名.
	Verify(data []byte, signature []byte) error

	// HybridEncrypt 混合加密: 结合对称加密和非对称加密.
	// RSA: 使用 RSA 加密 AES 密钥, AES 加密数据.
	// ECDSA/Ed25519: 使用 ECDH 密钥交换派生共享密钥, AES 加密数据.
	// 返回密文和 nonce, 如果 plaintext 为 nil, 则返回 nil 密文和有效的 nonce.
	HybridEncrypt(plaintext []byte) ([]byte, []byte, error)

	// HybridDecrypt 混合解密.
	HybridDecrypt(encryptedPackage []byte) ([]byte, error)

	// GetKeyAlgorithm 获取密钥算法.
	GetKeyAlgorithm() KeyAlgorithm

	// GetCertificate 获取底层证书.
	GetCertificate() *Certificate
}

// NewCertificate 从 PEM 格式的证书和私钥创建 Certificate 对象.
func NewCertificate(certPEM, keyPEM string) (*Certificate, error) {
	cert := &Certificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}

	// 解析证书.
	parsedCert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	cert.cert = parsedCert

	// 解析私钥.
	if keyPEM != "" {
		parsedKey, err := ParsePrivateKey(keyPEM)
		if err != nil {
			return nil, err
		}

		cert.privateKey = parsedKey
	}

	// 确定密钥算法.
	switch parsedCert.PublicKeyAlgorithm {
	case x509.RSA:
		cert.KeyAlgorithm = KeyAlgorithmRSA
	case x509.ECDSA:
		cert.KeyAlgorithm = KeyAlgorithmECDSA
	case x509.Ed25519:
		cert.KeyAlgorithm = KeyAlgorithmEd25519
	default:
		cert.KeyAlgorithm = KeyAlgorithm("Unknown")
	}

	return cert, nil
}

// NewCertificateFromCert 从已有的证书对象创建 Certificate(仅公钥, 无私钥).
func NewCertificateFromCert(certPEM string) (*Certificate, error) {
	return NewCertificate(certPEM, "")
}

// GetCryptoOperator 根据密钥算法返回对应的加密操作器.
func (c *Certificate) GetCryptoOperator() (CryptoOperator, error) {
	switch c.KeyAlgorithm {
	case KeyAlgorithmRSA:
		return &RSACryptoOperator{cert: c}, nil
	case KeyAlgorithmECDSA:
		return &ECDSACryptoOperator{cert: c}, nil
	case KeyAlgorithmEd25519:
		return &Ed25519CryptoOperator{cert: c}, nil
	default:
		return nil, errors.New("unsupported key algorithm")
	}
}

// GetParsedCert 获取解析后的 x509.Certificate.
func (c *Certificate) GetParsedCert() *x509.Certificate {
	return c.cert
}

// GetPrivateKey 获取解析后的私钥.
func (c *Certificate) GetPrivateKey() crypto.Signer {
	return c.privateKey
}

// HasPrivateKey 检查是否包含私钥.
func (c *Certificate) HasPrivateKey() bool {
	return c.privateKey != nil
}
