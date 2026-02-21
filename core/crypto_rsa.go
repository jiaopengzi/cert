//
// FilePath    : go-utils\cert\crypto_rsa.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : RSA 证书加密操作器
//

package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"github.com/jiaopengzi/cert/utils"
)

// RSACryptoOperator RSA 证书加密操作器.
type RSACryptoOperator struct {
	cert *Certificate
}

// GetKeyAlgorithm 获取密钥算法.
func (r *RSACryptoOperator) GetKeyAlgorithm() KeyAlgorithm {
	return KeyAlgorithmRSA
}

// GetCertificate 获取底层证书.
func (r *RSACryptoOperator) GetCertificate() *Certificate {
	return r.cert
}

// Sign 使用 RSA 私钥对数据进行签名(PKCS1v15 with SHA-256).
func (r *RSACryptoOperator) Sign(data []byte) ([]byte, error) {
	// 检查是否有私钥.
	if !r.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// 获取 RSA 私钥.
	rsaKey, ok := r.cert.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// 对数据进行哈希.
	hashed := sha256.Sum256(data)

	// 签名.
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("rsa sign failed: %w", err)
	}

	return signature, nil
}

// Verify 使用 RSA 公钥验证签名(PKCS1v15 with SHA-256).
func (r *RSACryptoOperator) Verify(data []byte, signature []byte) error {
	// 获取 RSA 公钥.
	pubKey, ok := r.cert.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKeyType
	}

	// 对数据进行哈希.
	hashed := sha256.Sum256(data)

	// 验证签名.
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("rsa verify failed: %w", err)
	}

	return nil
}

// HybridEncrypt 混合加密: 使用 AES 加密数据, 使用 RSA 加密 AES 密钥.
// 返回密文和 nonce, 如果 plaintext 为 nil, 则返回 nil 密文和有效的 nonce.
func (r *RSACryptoOperator) HybridEncrypt(plaintext []byte) ([]byte, []byte, error) {
	// 生成随机 AES 密钥.
	aesKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, nil, fmt.Errorf("generate aes key failed: %w", err)
	}

	// 使用 AES-GCM 加密数据.
	ciphertext, nonce, err := utils.GCMEncrypt(aesKey, plaintext)
	if err != nil {
		return nil, nil, err
	}

	// 如果 plaintext 为 nil, 只返回 nonce.
	if plaintext == nil {
		return nil, nonce, nil
	}

	// 使用 RSA-OAEP 加密 AES 密钥.
	pubKey, ok := r.cert.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, ErrInvalidKeyType
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt aes key failed: %w", err)
	}
	if len(encryptedKey) > 99999 {
		return nil, nil, fmt.Errorf("encrypted key too large: %d", len(encryptedKey))
	}

	// 组合加密包: [加密密钥长度(5字节十进制)][加密密钥][nonce][加密数据].
	keyLenHeader := fmt.Sprintf("%05d", len(encryptedKey))
	result := make([]byte, 5+len(encryptedKey)+len(nonce)+len(ciphertext))
	copy(result[:5], keyLenHeader)
	copy(result[5:], encryptedKey)
	copy(result[5+len(encryptedKey):], nonce)
	copy(result[5+len(encryptedKey)+len(nonce):], ciphertext)

	return result, nonce, nil
}

// HybridDecrypt 混合解密.
func (r *RSACryptoOperator) HybridDecrypt(encryptedPackage []byte) ([]byte, error) {
	// 使用 RSA-OAEP 解密 AES 密钥前先检查私钥.
	if !r.cert.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	rsaKey, ok := r.cert.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// 检查加密包长度.
	if len(encryptedPackage) < 5 {
		return nil, ErrInvalidCiphertext
	}

	// 解析加密包.
	keyLen, err := strconv.Atoi(string(encryptedPackage[:5]))
	if err != nil || keyLen < 0 {
		return nil, ErrInvalidCiphertext
	}
	if len(encryptedPackage) < 5+keyLen {
		return nil, ErrInvalidCiphertext
	}

	encryptedKey := encryptedPackage[5 : 5+keyLen]
	remaining := encryptedPackage[5+keyLen:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes key failed: %w", err)
	}

	// 检查剩余数据长度.
	nonceSize := utils.GCMNonceSize()
	if len(remaining) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	// 提取 nonce 和密文.
	nonce := remaining[:nonceSize]
	ciphertext := remaining[nonceSize:]

	// 使用 AES-GCM 解密数据.
	plaintext, err := utils.GCMDecrypt(aesKey, nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
