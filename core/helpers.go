//
// FilePath    : cert\core\helpers.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书便捷辅助函数
//

package core

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// EncryptWithCert 使用证书公钥加密数据(混合加密).
// 支持 RSA/ECDSA/Ed25519 证书.
// certPEM: 证书 PEM 格式字符串(仅需公钥).
// plaintext: 待加密的明文.
// 返回加密后的数据和 nonce.
func EncryptWithCert(certPEM string, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	// 创建仅包含公钥的证书对象.
	certificate, err := NewCertificateFromCert(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	// 获取加密操作器.
	operator, err := certificate.GetCryptoOperator()
	if err != nil {
		return nil, nil, fmt.Errorf("get crypto operator: %w", err)
	}

	// 混合加密.
	ciphertext, nonce, err = operator.HybridEncrypt(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("hybrid encrypt: %w", err)
	}

	return ciphertext, nonce, nil
}

// detectKeyAlgorithm 根据私钥类型检测密钥算法.
// privateKey: 私钥对象.
// 返回对应的 KeyAlgorithm, 如果不支持则返回错误.
func detectKeyAlgorithm(privateKey any) (KeyAlgorithm, error) {
	keyTypeName := fmt.Sprintf("%T", privateKey)

	switch {
	case strings.Contains(keyTypeName, "rsa"):
		return KeyAlgorithmRSA, nil
	case strings.Contains(keyTypeName, "ecdsa"):
		return KeyAlgorithmECDSA, nil
	case strings.Contains(keyTypeName, "ed25519"):
		return KeyAlgorithmEd25519, nil
	default:
		return "", errors.New("unsupported key algorithm")
	}
}

// DecryptWithKey 使用私钥解密数据(混合解密).
// keyPEM: 私钥 PEM 格式字符串.
// ciphertext: 待解密的密文.
// 返回解密后的明文.
func DecryptWithKey(keyPEM string, ciphertext []byte) ([]byte, error) {
	// 解析私钥获取算法类型.
	privateKey, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// 检测密钥算法.
	keyAlgorithm, err := detectKeyAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}

	// 创建临时证书对象(仅用于解密).
	certificate := &Certificate{
		KeyPEM:       keyPEM,
		privateKey:   privateKey,
		KeyAlgorithm: keyAlgorithm,
	}

	// 获取加密操作器.
	operator, err := certificate.GetCryptoOperator()
	if err != nil {
		return nil, fmt.Errorf("get crypto operator: %w", err)
	}

	// 混合解密.
	plaintext, err := operator.HybridDecrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("hybrid decrypt: %w", err)
	}

	return plaintext, nil
}

// SignData 使用私钥对数据进行签名.
// keyPEM: 私钥 PEM 格式字符串.
// data: 待签名的数据.
// 返回签名结果.
func SignData(keyPEM string, data []byte) ([]byte, error) {
	// 解析私钥获取算法类型.
	privateKey, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// 检测密钥算法.
	keyAlgorithm, err := detectKeyAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}

	// 创建临时证书对象(仅用于签名).
	certificate := &Certificate{
		KeyPEM:       keyPEM,
		privateKey:   privateKey,
		KeyAlgorithm: keyAlgorithm,
	}

	// 获取加密操作器.
	operator, err := certificate.GetCryptoOperator()
	if err != nil {
		return nil, fmt.Errorf("get crypto operator: %w", err)
	}

	// 签名.
	signature, err := operator.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}

	return signature, nil
}

// VerifySignature 使用证书公钥验证签名.
// certPEM: 证书 PEM 格式字符串.
// data: 原始数据.
// signature: 签名.
// 返回 nil 表示验证成功, 否则返回错误.
func VerifySignature(certPEM string, data, signature []byte) error {
	// 创建仅包含公钥的证书对象.
	certificate, err := NewCertificateFromCert(certPEM)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// 获取加密操作器.
	operator, err := certificate.GetCryptoOperator()
	if err != nil {
		return fmt.Errorf("get crypto operator: %w", err)
	}

	// 验证签名.
	if err := operator.Verify(data, signature); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	return nil
}

// 支持的哈希算法.
const (
	HashAlgoSHA256 = "sha256"
	HashAlgoSHA384 = "sha384"
	HashAlgoSHA512 = "sha512"
)

// GetCertFingerprint 计算证书指纹.
// certPEM: 证书 PEM 格式字符串.
// hashAlgo: 哈希算法, 支持 "sha256", "sha384", "sha512".
// 返回格式为 "算法:十六进制指纹" 的字符串, 例如 "sha256:abc123...".
func GetCertFingerprint(certPEM string, hashAlgo string) (string, error) {
	// 解析 PEM 块.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("failed to parse certificate PEM")
	}

	if block.Type != string(PEMBlockCertificate) {
		return "", fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	// 计算 DER 编码证书的哈希.
	var fingerprint string

	switch strings.ToLower(hashAlgo) {
	case HashAlgoSHA256:
		hash := sha256.Sum256(block.Bytes)
		fingerprint = hex.EncodeToString(hash[:])
	case HashAlgoSHA384:
		hash := sha512.Sum384(block.Bytes)
		fingerprint = hex.EncodeToString(hash[:])
	case HashAlgoSHA512:
		hash := sha512.Sum512(block.Bytes)
		fingerprint = hex.EncodeToString(hash[:])
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s, supported: sha256, sha384, sha512", hashAlgo)
	}

	return fmt.Sprintf("%s:%s", strings.ToLower(hashAlgo), fingerprint), nil
}

// EncodeCertForHeader 将 PEM 格式证书编码为 Base64 字符串(用于 HTTP Header).
// certPEM: 证书 PEM 格式字符串.
// 返回 Base64 编码的字符串.
func EncodeCertForHeader(certPEM string) string {
	return base64.StdEncoding.EncodeToString([]byte(certPEM))
}

// DecodeCertFromHeader 从 Base64 字符串解码为 PEM 格式证书(用于 HTTP Header).
// b64: Base64 编码的证书字符串.
// 返回 PEM 格式证书字符串.
func DecodeCertFromHeader(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	// 验证解码后的内容是有效的 PEM 格式.
	block, _ := pem.Decode(decoded)
	if block == nil {
		return "", errors.New("decoded content is not valid PEM format")
	}

	return string(decoded), nil
}
