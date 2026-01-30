//
// FilePath    : go-utils\crypto_aes_gcm_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : AES-GCM 加密解密通用工具函数测试
//

package utils

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// generateRandomKey 生成指定长度的随机密钥.
func generateRandomKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate random key failed: %v", err)
	}
	return key
}

func TestGCMEncrypt_Decrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
	}{
		{
			name:      "AES-128 with normal text",
			keySize:   16,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-192 with normal text",
			keySize:   24,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-256 with normal text",
			keySize:   32,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-256 with empty plaintext",
			keySize:   32,
			plaintext: []byte{},
		},
		{
			name:      "AES-256 with unicode text",
			keySize:   32,
			plaintext: []byte("你好, 世界! 🌍"),
		},
		{
			name:      "AES-256 with binary data",
			keySize:   32,
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:      "AES-256 with large data",
			keySize:   32,
			plaintext: bytes.Repeat([]byte("A"), 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateRandomKey(t, tt.keySize)

			// 加密.
			ciphertext, nonce, err := GCMEncrypt(key, tt.plaintext)
			if err != nil {
				t.Fatalf("GCMEncrypt failed: %v", err)
			}

			// 验证 nonce 长度.
			if len(nonce) != GCMNonceSize() {
				t.Errorf("nonce size = %d, want %d", len(nonce), GCMNonceSize())
			}

			// 解密.
			decrypted, err := GCMDecrypt(key, nonce, ciphertext)
			if err != nil {
				t.Fatalf("GCMDecrypt failed: %v", err)
			}

			// 验证解密结果.
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestGCMEncrypt_NilPlaintext(t *testing.T) {
	key := generateRandomKey(t, 32)

	ciphertext, nonce, err := GCMEncrypt(key, nil)
	if err != nil {
		t.Fatalf("GCMEncrypt with nil plaintext failed: %v", err)
	}

	// 密文应该为 nil.
	if ciphertext != nil {
		t.Errorf("ciphertext should be nil, got len=%d", len(ciphertext))
	}

	// nonce 应该有效.
	if len(nonce) != GCMNonceSize() {
		t.Errorf("nonce size = %d, want %d", len(nonce), GCMNonceSize())
	}
}

func TestGCMEncrypt_InvalidKeySize(t *testing.T) {
	invalidKeySizes := []int{0, 1, 15, 17, 23, 25, 31, 33, 64}

	for _, size := range invalidKeySizes {
		t.Run("key_size_"+string(rune('0'+size)), func(t *testing.T) {
			key := make([]byte, size)
			_, _, err := GCMEncrypt(key, []byte("test"))
			if err == nil {
				t.Errorf("GCMEncrypt should fail with key size %d", size)
			}
		})
	}
}

func TestGCMDecrypt_WrongKey(t *testing.T) {
	key1 := generateRandomKey(t, 32)
	key2 := generateRandomKey(t, 32)
	plaintext := []byte("secret message")

	// 使用 key1 加密.
	ciphertext, nonce, err := GCMEncrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// 使用 key2 解密应该失败.
	_, err = GCMDecrypt(key2, nonce, ciphertext)
	if err == nil {
		t.Error("GCMDecrypt should fail with wrong key")
	}
}

func TestGCMDecrypt_TamperedCiphertext(t *testing.T) {
	key := generateRandomKey(t, 32)
	plaintext := []byte("secret message")

	ciphertext, nonce, err := GCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// 篡改密文.
	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	_, err = GCMDecrypt(key, nonce, ciphertext)
	if err == nil {
		t.Error("GCMDecrypt should fail with tampered ciphertext")
	}
}

func TestGCMDecrypt_InvalidNonce(t *testing.T) {
	key := generateRandomKey(t, 32)
	plaintext := []byte("secret message")

	ciphertext, _, err := GCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// 使用错误的 nonce.
	wrongNonce := generateRandomKey(t, GCMNonceSize())
	_, err = GCMDecrypt(key, wrongNonce, ciphertext)
	if err == nil {
		t.Error("GCMDecrypt should fail with wrong nonce")
	}
}

func TestGCMEncryptWithNoncePrepended_Decrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
	}{
		{
			name:      "AES-128 with normal text",
			keySize:   16,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-192 with normal text",
			keySize:   24,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-256 with normal text",
			keySize:   32,
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "AES-256 with empty plaintext",
			keySize:   32,
			plaintext: []byte{},
		},
		{
			name:      "AES-256 with unicode text",
			keySize:   32,
			plaintext: []byte("你好, 世界! 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateRandomKey(t, tt.keySize)

			// 加密(nonce 前置).
			result, nonce, err := GCMEncryptWithNoncePrepended(key, tt.plaintext)
			if err != nil {
				t.Fatalf("GCMEncryptWithNoncePrepended failed: %v", err)
			}

			// 验证 nonce 长度.
			if len(nonce) != GCMNonceSize() {
				t.Errorf("nonce size = %d, want %d", len(nonce), GCMNonceSize())
			}

			// 验证 result 前缀包含 nonce.
			if !bytes.HasPrefix(result, nonce) {
				t.Error("result should have nonce as prefix")
			}

			// 解密.
			decrypted, err := GCMDecryptWithNoncePrepended(key, result)
			if err != nil {
				t.Fatalf("GCMDecryptWithNoncePrepended failed: %v", err)
			}

			// 验证解密结果.
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestGCMEncryptWithNoncePrepended_NilPlaintext(t *testing.T) {
	key := generateRandomKey(t, 32)

	result, nonce, err := GCMEncryptWithNoncePrepended(key, nil)
	if err != nil {
		t.Fatalf("GCMEncryptWithNoncePrepended with nil plaintext failed: %v", err)
	}

	// result 应该为 nil.
	if result != nil {
		t.Errorf("result should be nil, got len=%d", len(result))
	}

	// nonce 应该有效.
	if len(nonce) != GCMNonceSize() {
		t.Errorf("nonce size = %d, want %d", len(nonce), GCMNonceSize())
	}
}

func TestGCMDecryptWithNoncePrepended_CiphertextTooShort(t *testing.T) {
	key := generateRandomKey(t, 32)

	// 密文长度小于 nonce 大小.
	shortCiphertext := make([]byte, GCMNonceSize()-1)
	_, err := GCMDecryptWithNoncePrepended(key, shortCiphertext)
	if err == nil {
		t.Error("GCMDecryptWithNoncePrepended should fail with short ciphertext")
	}
}

func TestGCMDecryptWithNoncePrepended_WrongKey(t *testing.T) {
	key1 := generateRandomKey(t, 32)
	key2 := generateRandomKey(t, 32)
	plaintext := []byte("secret message")

	// 使用 key1 加密.
	result, _, err := GCMEncryptWithNoncePrepended(key1, plaintext)
	if err != nil {
		t.Fatalf("GCMEncryptWithNoncePrepended failed: %v", err)
	}

	// 使用 key2 解密应该失败.
	_, err = GCMDecryptWithNoncePrepended(key2, result)
	if err == nil {
		t.Error("GCMDecryptWithNoncePrepended should fail with wrong key")
	}
}

func TestGCMDecryptWithNoncePrepended_TamperedCiphertext(t *testing.T) {
	key := generateRandomKey(t, 32)
	plaintext := []byte("secret message")

	result, _, err := GCMEncryptWithNoncePrepended(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncryptWithNoncePrepended failed: %v", err)
	}

	// 篡改密文部分(跳过 nonce).
	if len(result) > GCMNonceSize() {
		result[GCMNonceSize()] ^= 0xFF
	}

	_, err = GCMDecryptWithNoncePrepended(key, result)
	if err == nil {
		t.Error("GCMDecryptWithNoncePrepended should fail with tampered ciphertext")
	}
}

func TestGCMNonceSize(t *testing.T) {
	size := GCMNonceSize()
	if size != 12 {
		t.Errorf("GCMNonceSize() = %d, want 12", size)
	}
}

func TestGenerateGCMNonce(t *testing.T) {
	nonce1, err := GenerateGCMNonce()
	if err != nil {
		t.Fatalf("GenerateGCMNonce failed: %v", err)
	}

	// 验证长度.
	if len(nonce1) != GCMNonceSize() {
		t.Errorf("nonce size = %d, want %d", len(nonce1), GCMNonceSize())
	}

	// 验证随机性 - 多次生成应该不同.
	nonce2, err := GenerateGCMNonce()
	if err != nil {
		t.Fatalf("GenerateGCMNonce failed: %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Error("two generated nonces should be different")
	}
}

func TestGCMEncrypt_Uniqueness(t *testing.T) {
	key := generateRandomKey(t, 32)
	plaintext := []byte("same message")

	// 多次加密相同明文应该产生不同密文(因为 nonce 不同).
	ciphertext1, nonce1, err := GCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	ciphertext2, nonce2, err := GCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// nonce 应该不同.
	if bytes.Equal(nonce1, nonce2) {
		t.Error("two nonces should be different")
	}

	// 密文应该不同.
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("two cipher text should be different")
	}
}

func TestGCMEncryptWithNoncePrepended_Uniqueness(t *testing.T) {
	key := generateRandomKey(t, 32)
	plaintext := []byte("same message")

	// 多次加密相同明文应该产生不同结果.
	result1, _, err := GCMEncryptWithNoncePrepended(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncryptWithNoncePrepended failed: %v", err)
	}

	result2, _, err := GCMEncryptWithNoncePrepended(key, plaintext)
	if err != nil {
		t.Fatalf("GCMEncryptWithNoncePrepended failed: %v", err)
	}

	if bytes.Equal(result1, result2) {
		t.Error("two results should be different")
	}
}

func TestGCMDecrypt_InvalidKeySize(t *testing.T) {
	invalidKeySizes := []int{0, 1, 15, 17, 23, 25, 31, 33}

	for _, size := range invalidKeySizes {
		t.Run("key_size_"+string(rune('0'+size)), func(t *testing.T) {
			key := make([]byte, size)
			nonce := make([]byte, GCMNonceSize())
			_, err := GCMDecrypt(key, nonce, []byte("test"))
			if err == nil {
				t.Errorf("GCMDecrypt should fail with key size %d", size)
			}
		})
	}
}

func TestGCMDecryptWithNoncePrepended_InvalidKeySize(t *testing.T) {
	invalidKeySizes := []int{0, 1, 15, 17, 23, 25, 31, 33}

	for _, size := range invalidKeySizes {
		t.Run("key_size_"+string(rune('0'+size)), func(t *testing.T) {
			key := make([]byte, size)
			// 创建一个足够长的密文(至少包含 nonce).
			ciphertext := make([]byte, GCMNonceSize()+10)
			_, err := GCMDecryptWithNoncePrepended(key, ciphertext)
			if err == nil {
				t.Errorf("GCMDecryptWithNoncePrepended should fail with key size %d", size)
			}
		})
	}
}
