//
// FilePath    : cert\core\crypto_ecdsa.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : ECDSA 证书加密操作器
//

package core

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/jiaopengzi/go-utils"
)

// ECDSACryptoOperator ECDSA 证书加密操作器.
type ECDSACryptoOperator struct {
	cert *Certificate
}

// GetKeyAlgorithm 获取密钥算法.
func (e *ECDSACryptoOperator) GetKeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithmECDSA
}

// GetCertificate 获取底层证书.
func (e *ECDSACryptoOperator) GetCertificate() *Certificate {
	return e.cert
}

// Sign 使用 ECDSA 私钥对数据进行签名.
func (e *ECDSACryptoOperator) Sign(data []byte) ([]byte, error) {
	// 检查是否有私钥.
	if !e.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// 获取 ECDSA 私钥.
	ecdsaKey, ok := e.cert.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// 对数据进行哈希.
	hashed := sha256.Sum256(data)

	// 签名.
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}

	// 将 r 和 s 编码为固定长度的字节数组.
	// 每个值固定为 32 字节(256 位), 总共 64 字节.
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

// Verify 使用 ECDSA 公钥验证签名.
func (e *ECDSACryptoOperator) Verify(data []byte, signature []byte) error {
	// 获取 ECDSA 公钥.
	pubKey, ok := e.cert.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidKeyType
	}

	// 检查签名长度.
	if len(signature) != 64 {
		return ErrInvalidSignature
	}

	// 解析 r 和 s.
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// 对数据进行哈希.
	hashed := sha256.Sum256(data)

	// 验证签名.
	if !ecdsa.Verify(pubKey, hashed[:], r, s) {
		return ErrInvalidSignature
	}

	return nil
}

// HybridEncrypt 混合加密, 使用 ECDH 密钥交换派生共享密钥, AES 加密数据.
// 返回密文和 nonce, 如果 plaintext 为 nil, 则返回 nil 密文和有效的 nonce.
func (e *ECDSACryptoOperator) HybridEncrypt(plaintext []byte) ([]byte, []byte, error) {
	// 获取 ECDSA 公钥.
	ecdsaPubKey, ok := e.cert.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, ErrInvalidKeyType
	}

	// 将 ECDSA 公钥转换为 ECDH 公钥.
	ecdhCurve, err := ecdsaCurveToECDH(ecdsaPubKey.Curve.Params().Name)
	if err != nil {
		return nil, nil, err
	}

	// 将 ECDSA 公钥转换为 ECDH 公钥.
	recipientECDHPubKey, err := ecdsaPublicKeyToECDH(ecdsaPubKey, ecdhCurve)
	if err != nil {
		return nil, nil, fmt.Errorf("convert ecdsa public key to ecdh failed: %w", err)
	}

	// 生成临时 ECDH 密钥对.
	ephemeralKey, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key failed: %w", err)
	}

	// 执行 ECDH 密钥交换.
	sharedSecret, err := ephemeralKey.ECDH(recipientECDHPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh key exchange failed: %w", err)
	}

	// 使用 SHA-256 派生 AES 密钥.
	aesKey := sha256.Sum256(sharedSecret)

	// 使用 AES-GCM 加密数据.
	ciphertext, nonce, err := utils.GCMEncrypt(aesKey[:], plaintext)
	if err != nil {
		return nil, nil, err
	}

	// 如果 plaintext 为 nil, 只返回 nonce.
	if plaintext == nil {
		return nil, nonce, nil
	}

	// 获取临时公钥字节.
	ephemeralPubBytes := ephemeralKey.PublicKey().Bytes()

	// 组合加密包: [临时公钥长度(1字节)][临时公钥][nonce][加密数据].
	result := make([]byte, 1+len(ephemeralPubBytes)+len(nonce)+len(ciphertext))
	result[0] = byte(len(ephemeralPubBytes))
	copy(result[1:], ephemeralPubBytes)
	copy(result[1+len(ephemeralPubBytes):], nonce)
	copy(result[1+len(ephemeralPubBytes)+len(nonce):], ciphertext)

	return result, nonce, nil
}

// HybridDecrypt 混合解密.
func (e *ECDSACryptoOperator) HybridDecrypt(encryptedPackage []byte) ([]byte, error) {
	// 检查是否有私钥.
	if !e.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// 获取 ECDSA 私钥.
	ecdsaKey, ok := e.cert.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// 检查加密包长度.
	if len(encryptedPackage) < 1 {
		return nil, ErrInvalidCiphertext
	}

	// 解析加密包.
	pubKeyLen := int(encryptedPackage[0])
	if len(encryptedPackage) < 1+pubKeyLen {
		return nil, ErrInvalidCiphertext
	}

	// 解析临时公钥和剩余数据.
	ephemeralPubBytes := encryptedPackage[1 : 1+pubKeyLen]
	remaining := encryptedPackage[1+pubKeyLen:]

	// 将 ECDSA 私钥转换为 ECDH 私钥.
	ecdhCurve, err := ecdsaCurveToECDH(ecdsaKey.Curve.Params().Name)
	if err != nil {
		return nil, err
	}

	// 协议系统转换 ECDSA 私钥为 ECDH 私钥.
	recipientECDHPrivKey, err := ecdsaPrivateKeyToECDH(ecdsaKey, ecdhCurve)
	if err != nil {
		return nil, fmt.Errorf("convert ecdsa private key to ecdh failed: %w", err)
	}

	// 解析临时公钥.
	ephemeralPubKey, err := ecdhCurve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key failed: %w", err)
	}

	// 执行 ECDH 密钥交换.
	sharedSecret, err := recipientECDHPrivKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh key exchange failed: %w", err)
	}

	// 使用 SHA-256 派生 AES 密钥.
	aesKey := sha256.Sum256(sharedSecret)

	// 检查剩余数据长度.
	nonceSize := utils.GCMNonceSize()
	if len(remaining) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	// 提取 nonce 和密文.
	nonce := remaining[:nonceSize]
	ciphertext := remaining[nonceSize:]

	// 使用 AES-GCM 解密数据.
	plaintext, err := utils.GCMDecrypt(aesKey[:], nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ecdsaCurveToECDH 将 ECDSA 曲线名称转换为 ECDH 曲线.
func ecdsaCurveToECDH(curveName string) (ecdh.Curve, error) {
	switch curveName {
	case "P-256":
		return ecdh.P256(), nil
	case "P-384":
		return ecdh.P384(), nil
	case "P-521":
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}
}

// ecdsaPublicKeyToECDH 将 ECDSA 公钥转换为 ECDH 公钥.
func ecdsaPublicKeyToECDH(pubKey *ecdsa.PublicKey, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	// ECDH 公钥使用未压缩格式: 0x04 || X || Y.
	byteLen := (pubKey.Curve.Params().BitSize + 7) / 8
	pubBytes := make([]byte, 1+2*byteLen)
	pubBytes[0] = 0x04

	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	copy(pubBytes[1+byteLen-len(xBytes):1+byteLen], xBytes)
	copy(pubBytes[1+2*byteLen-len(yBytes):1+2*byteLen], yBytes)

	return curve.NewPublicKey(pubBytes)
}

// ecdsaPrivateKeyToECDH 将 ECDSA 私钥转换为 ECDH 私钥.
func ecdsaPrivateKeyToECDH(privKey *ecdsa.PrivateKey, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	// ECDH 私钥是固定长度的标量.
	byteLen := (privKey.Curve.Params().BitSize + 7) / 8
	privBytes := make([]byte, byteLen)

	dBytes := privKey.D.Bytes()
	copy(privBytes[byteLen-len(dBytes):], dBytes)

	return curve.NewPrivateKey(privBytes)
}
