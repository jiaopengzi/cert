//
// FilePath    : cert\core\crypto_ed25519.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : Ed25519 证书加密操作器
//

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"github.com/jiaopengzi/go-utils"
	"golang.org/x/crypto/curve25519"
)

// Ed25519CryptoOperator Ed25519 证书加密操作器.
type Ed25519CryptoOperator struct {
	cert *Certificate
}

// GetKeyAlgorithm 获取密钥算法.
func (e *Ed25519CryptoOperator) GetKeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithmEd25519
}

// GetCertificate 获取底层证书.
func (e *Ed25519CryptoOperator) GetCertificate() *Certificate {
	return e.cert
}

// Sign 使用 Ed25519 私钥对数据进行签名.
func (e *Ed25519CryptoOperator) Sign(data []byte) ([]byte, error) {
	// 检查是否有私钥.
	if !e.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// 获取 Ed25519 私钥.
	ed25519Key, ok := e.cert.privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// Ed25519 签名不需要预先哈希.
	signature := ed25519.Sign(ed25519Key, data)

	return signature, nil
}

// Verify 使用 Ed25519 公钥验证签名.
func (e *Ed25519CryptoOperator) Verify(data []byte, signature []byte) error {
	// 获取 Ed25519 公钥.
	pubKey, ok := e.cert.cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ErrInvalidKeyType
	}

	// 检查签名长度.
	if len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	// 验证签名.
	if !ed25519.Verify(pubKey, data, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// HybridEncrypt 混合加密: 使用 X25519 ECDH 密钥交换派生共享密钥, AES 加密数据.
// Ed25519 公钥会被转换为 X25519 公钥用于密钥交换.
// 返回密文和 nonce, 如果 plaintext 为 nil, 则返回 nil 密文和有效的 nonce.
func (e *Ed25519CryptoOperator) HybridEncrypt(plaintext []byte) ([]byte, []byte, error) {
	// 获取 Ed25519 公钥.
	pubKey, ok := e.cert.cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, ErrInvalidKeyType
	}

	// 将 Ed25519 公钥转换为 X25519 公钥.
	recipientX25519PubKey, err := ed25519PublicKeyToX25519(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("convert ed25519 to x25519 public key failed: %w", err)
	}

	// 生成临时 X25519 密钥对.
	var ephemeralPrivKey [32]byte
	if _, randErr := io.ReadFull(rand.Reader, ephemeralPrivKey[:]); randErr != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key failed: %w", randErr)
	}

	// 计算临时公钥.
	ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("compute ephemeral public key failed: %w", err)
	}

	// 执行 ECDH 密钥交换, 得到共享密钥.
	sharedSecret, err := curve25519.X25519(ephemeralPrivKey[:], recipientX25519PubKey)
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

	// 组合加密包: [临时公钥(32字节)][nonce][加密数据].
	result := make([]byte, 32+len(nonce)+len(ciphertext))
	copy(result[:32], ephemeralPubKey)
	copy(result[32:32+len(nonce)], nonce)
	copy(result[32+len(nonce):], ciphertext)

	return result, nonce, nil
}

// HybridDecrypt 混合解密.
func (e *Ed25519CryptoOperator) HybridDecrypt(encryptedPackage []byte) ([]byte, error) {
	// 检查是否有私钥.
	if !e.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// 获取 Ed25519 私钥.
	if len(encryptedPackage) < 32 {
		return nil, ErrInvalidCiphertext
	}

	// 获取 Ed25519 私钥.
	ed25519Key, ok := e.cert.privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// 将 Ed25519 私钥转换为 X25519 私钥.
	x25519PrivKey, err := ed25519PrivateKeyToX25519(ed25519Key)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 to x25519 private key failed: %w", err)
	}

	// 提取临时公钥和剩余数据.
	ephemeralPubKey := encryptedPackage[:32]
	remaining := encryptedPackage[32:]

	// 执行 ECDH 密钥交换, 恢复共享密钥.
	sharedSecret, err := curve25519.X25519(x25519PrivKey, ephemeralPubKey)
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

// ed25519PublicKeyToX25519 将 Ed25519 公钥转换为 X25519 公钥.
// 使用 filippo.io/edwards25519 库进行正确的曲线点转换.
// Ed25519 公钥是 Edwards 曲线上的点, X25519 公钥是 Montgomery 曲线上的点.
// 转换公式: u = (1 + y) / (1 - y).
func ed25519PublicKeyToX25519(ed25519PubKey ed25519.PublicKey) ([]byte, error) {
	if len(ed25519PubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}

	// 使用 filippo.io/edwards25519 库解析 Ed25519 公钥点.
	point, err := new(edwards25519.Point).SetBytes(ed25519PubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %w", err)
	}

	// 转换为 Montgomery 形式 (X25519).
	// BytesMontgomery 返回 X25519 公钥.
	return point.BytesMontgomery(), nil
}

// ed25519PrivateKeyToX25519 将 Ed25519 私钥转换为 X25519 私钥.
func ed25519PrivateKeyToX25519(ed25519PrivKey ed25519.PrivateKey) ([]byte, error) {
	if len(ed25519PrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}

	// Ed25519 私钥的前 32 字节是种子.
	seed := ed25519PrivKey[:32]

	// 使用 SHA-512 哈希种子, 取前 32 字节作为 X25519 私钥.
	hash := sha512.Sum512(seed)

	// 按照 X25519 规范进行钳制(clamping).
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64

	return hash[:32], nil
}
