//
// FilePath    : cert\core\crypto_benchmark_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : Crypto 性能基准测试
//

package core

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// 测试数据大小
var benchmarkDataSizes = []int{
	64,      // 64 bytes
	1024,    // 1 KB
	16384,   // 16 KB
	65536,   // 64 KB
	1048576, // 1 MB
}

// 生成测试证书
func setupBenchmarkCerts(b *testing.B) (rsaOp, ecdsaOp, ed25519Op CryptoOperator) {
	b.Helper()

	// RSA 证书
	rsaCfg := &CACertConfig{
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		DaysValid:    1,
	}
	if err := GenCACert(rsaCfg); err != nil {
		b.Fatalf("生成 RSA 证书失败: %v", err)
	}
	rsaCertObj, err := NewCertificate(rsaCfg.Cert, rsaCfg.Key)
	if err != nil {
		b.Fatalf("创建 RSA 证书对象失败: %v", err)
	}
	rsaOp, _ = rsaCertObj.GetCryptoOperator()

	// ECDSA 证书
	ecdsaCfg := &CACertConfig{
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   "P256",
		DaysValid:    1,
	}
	if err := GenCACert(ecdsaCfg); err != nil {
		b.Fatalf("生成 ECDSA 证书失败: %v", err)
	}
	ecdsaCertObj, err := NewCertificate(ecdsaCfg.Cert, ecdsaCfg.Key)
	if err != nil {
		b.Fatalf("创建 ECDSA 证书对象失败: %v", err)
	}
	ecdsaOp, _ = ecdsaCertObj.GetCryptoOperator()

	// Ed25519 证书
	ed25519Cfg := &CACertConfig{
		KeyAlgorithm: KeyAlgorithmEd25519,
		DaysValid:    1,
	}
	if err := GenCACert(ed25519Cfg); err != nil {
		b.Fatalf("生成 Ed25519 证书失败: %v", err)
	}
	ed25519CertObj, err := NewCertificate(ed25519Cfg.Cert, ed25519Cfg.Key)
	if err != nil {
		b.Fatalf("创建 Ed25519 证书对象失败: %v", err)
	}
	ed25519Op, _ = ed25519CertObj.GetCryptoOperator()

	return rsaOp, ecdsaOp, ed25519Op
}

// 生成随机数据
func generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// ==================== 混合加密基准测试 ====================

func BenchmarkHybridEncrypt_RSA(b *testing.B) {
	rsaOp, _, _ := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := rsaOp.HybridEncrypt(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHybridEncrypt_ECDSA(b *testing.B) {
	_, ecdsaOp, _ := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := ecdsaOp.HybridEncrypt(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHybridEncrypt_Ed25519(b *testing.B) {
	_, _, ed25519Op := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := ed25519Op.HybridEncrypt(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ==================== 混合解密基准测试 ====================

func BenchmarkHybridDecrypt_RSA(b *testing.B) {
	rsaOp, _, _ := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		encrypted, _, err := rsaOp.HybridEncrypt(data)
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := rsaOp.HybridDecrypt(encrypted)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHybridDecrypt_ECDSA(b *testing.B) {
	_, ecdsaOp, _ := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		encrypted, _, err := ecdsaOp.HybridEncrypt(data)
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ecdsaOp.HybridDecrypt(encrypted)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHybridDecrypt_Ed25519(b *testing.B) {
	_, _, ed25519Op := setupBenchmarkCerts(b)

	for _, size := range benchmarkDataSizes {
		data := generateRandomData(size)
		encrypted, _, err := ed25519Op.HybridEncrypt(data)
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ed25519Op.HybridDecrypt(encrypted)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ==================== 对比测试（固定数据大小）====================

func BenchmarkHybridEncryptCompare_1KB(b *testing.B) {
	rsaOp, ecdsaOp, ed25519Op := setupBenchmarkCerts(b)
	data := generateRandomData(1024)

	b.Run("RSA-2048", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			rsaOp.HybridEncrypt(data)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			ecdsaOp.HybridEncrypt(data)
		}
	})

	b.Run("Ed25519-X25519", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			ed25519Op.HybridEncrypt(data)
		}
	})
}

func BenchmarkHybridDecryptCompare_1KB(b *testing.B) {
	rsaOp, ecdsaOp, ed25519Op := setupBenchmarkCerts(b)
	data := generateRandomData(1024)

	rsaEncrypted, _, _ := rsaOp.HybridEncrypt(data)
	ecdsaEncrypted, _, _ := ecdsaOp.HybridEncrypt(data)
	ed25519Encrypted, _, _ := ed25519Op.HybridEncrypt(data)

	b.Run("RSA-2048", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			rsaOp.HybridDecrypt(rsaEncrypted)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			ecdsaOp.HybridDecrypt(ecdsaEncrypted)
		}
	})

	b.Run("Ed25519-X25519", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			ed25519Op.HybridDecrypt(ed25519Encrypted)
		}
	})
}

// ==================== 完整加解密周期测试 ====================

func BenchmarkHybridRoundTrip_1KB(b *testing.B) {
	rsaOp, ecdsaOp, ed25519Op := setupBenchmarkCerts(b)
	data := generateRandomData(1024)

	b.Run("RSA-2048", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			encrypted, _, _ := rsaOp.HybridEncrypt(data)
			rsaOp.HybridDecrypt(encrypted)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			encrypted, _, _ := ecdsaOp.HybridEncrypt(data)
			ecdsaOp.HybridDecrypt(encrypted)
		}
	})

	b.Run("Ed25519-X25519", func(b *testing.B) {
		b.SetBytes(1024)
		for i := 0; i < b.N; i++ {
			encrypted, _, _ := ed25519Op.HybridEncrypt(data)
			ed25519Op.HybridDecrypt(encrypted)
		}
	})
}

// ==================== 签名性能对比 ====================

func BenchmarkSignCompare(b *testing.B) {
	rsaOp, ecdsaOp, ed25519Op := setupBenchmarkCerts(b)
	data := generateRandomData(256)

	b.Run("RSA-2048", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rsaOp.Sign(data)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ecdsaOp.Sign(data)
		}
	})

	b.Run("Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed25519Op.Sign(data)
		}
	})
}

func BenchmarkVerifyCompare(b *testing.B) {
	rsaOp, ecdsaOp, ed25519Op := setupBenchmarkCerts(b)
	data := generateRandomData(256)

	rsaSig, _ := rsaOp.Sign(data)
	ecdsaSig, _ := ecdsaOp.Sign(data)
	ed25519Sig, _ := ed25519Op.Sign(data)

	b.Run("RSA-2048", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rsaOp.Verify(data, rsaSig)
		}
	})

	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ecdsaOp.Verify(data, ecdsaSig)
		}
	})

	b.Run("Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed25519Op.Verify(data, ed25519Sig)
		}
	})
}
