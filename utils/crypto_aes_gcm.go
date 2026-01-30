//
// FilePath    : cert\utils\crypto_aes_gcm.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : AES-GCM 加密解密通用工具函数
//

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// GCMEncrypt 使用 AES-GCM 模式加密数据.
// 参数:
//   - aesKey: AES 密钥, 支持 16, 24 或 32 字节(对应 AES-128, AES-192, AES-256).
//   - plaintext: 待加密的明文数据, 如果为 nil, 则返回 nil 密文和有效的 nonce.
//
// 返回值:
//   - ciphertext: 加密后的密文(不包含 nonce).
//   - nonce: 随机生成的 nonce(GCM 推荐 12 字节).
//   - error: 错误信息.
func GCMEncrypt(aesKey []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	// 创建 AES cipher.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create aes cipher failed: %w", err)
	}

	// 创建 GCM 模式.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create gcm failed: %w", err)
	}

	// 生成随机 nonce(GCM 推荐 12 字节).
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce failed: %w", err)
	}

	// 如果 plaintext 为 nil, 只返回 nonce.
	if plaintext == nil {
		return nil, nonce, nil
	}

	// 加密数据.
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// GCMDecrypt 使用 AES-GCM 模式解密数据.
// 参数:
//   - aesKey: AES 密钥, 支持 16, 24 或 32 字节(对应 AES-128, AES-192, AES-256).
//   - nonce: 加密时生成的 nonce.
//   - ciphertext: 待解密的密文.
//
// 返回值:
//   - plaintext: 解密后的明文数据.
//   - error: 错误信息.
func GCMDecrypt(aesKey []byte, nonce []byte, ciphertext []byte) (plaintext []byte, err error) {
	// 创建 AES cipher.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher failed: %w", err)
	}

	// 创建 GCM 模式.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm failed: %w", err)
	}

	// 解密数据.
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data failed: %w", err)
	}

	return plaintext, nil
}

// GCMEncryptWithNoncePrepended 使用 AES-GCM 模式加密数据, 并将 nonce 前置到密文中.
// 参数:
//   - aesKey: AES 密钥, 支持 16, 24 或 32 字节(对应 AES-128, AES-192, AES-256).
//   - plaintext: 待加密的明文数据, 如果为 nil, 则返回 nil 密文和有效的 nonce.
//
// 返回值:
//   - result: nonce + 密文的组合数据.
//   - nonce: 随机生成的 nonce.
//   - error: 错误信息.
func GCMEncryptWithNoncePrepended(aesKey []byte, plaintext []byte) (result []byte, nonce []byte, err error) {
	// 创建 AES cipher.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create aes cipher failed: %w", err)
	}

	// 创建 GCM 模式.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create gcm failed: %w", err)
	}

	// 生成随机 nonce(GCM 推荐 12 字节).
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce failed: %w", err)
	}

	// 如果 plaintext 为 nil, 只返回 nonce.
	if plaintext == nil {
		return nil, nonce, nil
	}

	// 加密数据, nonce 作为前缀.
	result = gcm.Seal(nonce, nonce, plaintext, nil)

	return result, nonce, nil
}

// GCMDecryptWithNoncePrepended 解密 nonce 前置的密文数据.
// 参数:
//   - aesKey: AES 密钥, 支持 16, 24 或 32 字节(对应 AES-128, AES-192, AES-256).
//   - ciphertext: nonce + 密文的组合数据.
//
// 返回值:
//   - plaintext: 解密后的明文数据.
//   - error: 错误信息.
func GCMDecryptWithNoncePrepended(aesKey []byte, ciphertext []byte) (plaintext []byte, err error) {
	// 创建 AES cipher.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher failed: %w", err)
	}

	// 创建 GCM 模式.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm failed: %w", err)
	}

	// 检查密文长度.
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// 提取 nonce 和密文.
	nonce, ciphertextData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 解密数据.
	plaintext, err = gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data failed: %w", err)
	}

	return plaintext, nil
}

// GCMNonceSize 返回 GCM 模式的 nonce 大小(通常为 12 字节).
func GCMNonceSize() int {
	return 12
}

// GenerateGCMNonce 生成一个随机的 GCM nonce.
// 返回值:
//   - nonce: 随机生成的 nonce(12 字节).
//   - error: 错误信息.
func GenerateGCMNonce() ([]byte, error) {
	nonce := make([]byte, GCMNonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce failed: %w", err)
	}

	return nonce, nil
}
