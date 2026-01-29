//
// FilePath    : cert\core\crypto_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : Crypto 证书加密操作器单元测试
//

package core

import (
	"testing"
)

func TestRSACryptoOperator(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("gen ca cert failed: %v", err)
	}

	// 生成 RSA 证书.
	rsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "rsa-test",
		Subject:      Subject{CommonName: "rsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(rsaCfg); err != nil {
		t.Fatalf("gen rsa cert failed: %v", err)
	}

	// 创建证书对象.
	cert, err := NewCertificate(rsaCfg.Cert, rsaCfg.Key)
	if err != nil {
		t.Fatalf("new certificate failed: %v", err)
	}

	// 获取加密操作器.
	operator, err := cert.GetCryptoOperator()
	if err != nil {
		t.Fatalf("get crypto operator failed: %v", err)
	}

	// 验证密钥算法.
	if operator.GetKeyAlgorithm() != KeyAlgorithmRSA {
		t.Errorf("expected key algorithm RSA, got %v", operator.GetKeyAlgorithm())
	}

	t.Run("Sign_Verify", func(t *testing.T) {
		data := []byte("Data to sign")

		// 签名.
		signature, err := operator.Sign(data)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		// 验签.
		if err := operator.Verify(data, signature); err != nil {
			t.Fatalf("verify failed: %v", err)
		}

		// 验证篡改后的数据应该失败.
		tamperedData := []byte("Tampered data")
		if err := operator.Verify(tamperedData, signature); err == nil {
			t.Error("verify should fail for tampered data")
		}
	})

	t.Run("HybridEncrypt_Decrypt", func(t *testing.T) {
		plaintext := []byte("Large data for hybrid encryption. This is a longer message that would benefit from hybrid encryption.")

		// 混合加密.
		encrypted, nonce, err := operator.HybridEncrypt(plaintext)
		if err != nil {
			t.Fatalf("hybrid encrypt failed: %v", err)
		}
		if len(nonce) == 0 {
			t.Error("nonce should not be empty")
		}

		// 混合解密.
		decrypted, err := operator.HybridDecrypt(encrypted)
		if err != nil {
			t.Fatalf("hybrid decrypt failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("decrypted data mismatch")
		}
	})

	t.Run("HybridEncrypt_NilData", func(t *testing.T) {
		// 测试 nil 数据加密.
		encrypted, nonce, err := operator.HybridEncrypt(nil)
		if err != nil {
			t.Fatalf("hybrid encrypt nil data failed: %v", err)
		}

		// nonce 应该有效.
		if len(nonce) == 0 {
			t.Error("nonce should not be empty for nil data")
		}

		// 密文应该为 nil.
		if encrypted != nil {
			t.Errorf("encrypted should be nil for nil plaintext, got len=%d", len(encrypted))
		}
	})
}

func TestECDSACryptoOperator(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("gen ca cert failed: %v", err)
	}

	// 生成 ECDSA 证书.
	ecdsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ecdsa-test",
		Subject:      Subject{CommonName: "ecdsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   CurveP256,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(ecdsaCfg); err != nil {
		t.Fatalf("gen ecdsa cert failed: %v", err)
	}

	// 创建证书对象.
	cert, err := NewCertificate(ecdsaCfg.Cert, ecdsaCfg.Key)
	if err != nil {
		t.Fatalf("new certificate failed: %v", err)
	}

	// 获取加密操作器.
	operator, err := cert.GetCryptoOperator()
	if err != nil {
		t.Fatalf("get crypto operator failed: %v", err)
	}

	// 验证密钥算法.
	if operator.GetKeyAlgorithm() != KeyAlgorithmECDSA {
		t.Errorf("expected key algorithm ECDSA, got %v", operator.GetKeyAlgorithm())
	}

	t.Run("Sign_Verify", func(t *testing.T) {
		data := []byte("Data to sign with ECDSA")

		// 签名.
		signature, err := operator.Sign(data)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		// 验签.
		if err := operator.Verify(data, signature); err != nil {
			t.Fatalf("verify failed: %v", err)
		}

		// 验证篡改后的数据应该失败.
		tamperedData := []byte("Tampered data")
		if err := operator.Verify(tamperedData, signature); err == nil {
			t.Error("verify should fail for tampered data")
		}
	})

	t.Run("HybridEncrypt_Decrypt", func(t *testing.T) {
		plaintext := []byte("Large data for ECDSA hybrid encryption.")

		// 混合加密.
		encrypted, nonce, err := operator.HybridEncrypt(plaintext)
		if err != nil {
			t.Fatalf("hybrid encrypt failed: %v", err)
		}
		if len(nonce) == 0 {
			t.Error("nonce should not be empty")
		}

		// 混合解密.
		decrypted, err := operator.HybridDecrypt(encrypted)
		if err != nil {
			t.Fatalf("hybrid decrypt failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("decrypted data mismatch")
		}
	})

	t.Run("HybridEncrypt_NilData", func(t *testing.T) {
		// 测试 nil 数据加密.
		encrypted, nonce, err := operator.HybridEncrypt(nil)
		if err != nil {
			t.Fatalf("hybrid encrypt nil data failed: %v", err)
		}

		// nonce 应该有效.
		if len(nonce) == 0 {
			t.Error("nonce should not be empty for nil data")
		}

		// 密文应该为 nil.
		if encrypted != nil {
			t.Errorf("encrypted should be nil for nil plaintext, got len=%d", len(encrypted))
		}
	})
}

func TestEd25519CryptoOperator(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmEd25519,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("gen ca cert failed: %v", err)
	}

	// 生成 Ed25519 证书.
	ed25519Cfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "ed25519-test",
		Subject:      Subject{CommonName: "ed25519-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmEd25519,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(ed25519Cfg); err != nil {
		t.Fatalf("gen ed25519 cert failed: %v", err)
	}

	// 创建证书对象.
	cert, err := NewCertificate(ed25519Cfg.Cert, ed25519Cfg.Key)
	if err != nil {
		t.Fatalf("new certificate failed: %v", err)
	}

	// 获取加密操作器.
	operator, err := cert.GetCryptoOperator()
	if err != nil {
		t.Fatalf("get crypto operator failed: %v", err)
	}

	// 验证密钥算法.
	if operator.GetKeyAlgorithm() != KeyAlgorithmEd25519 {
		t.Errorf("expected key algorithm Ed25519, got %v", operator.GetKeyAlgorithm())
	}

	t.Run("Sign_Verify", func(t *testing.T) {
		data := []byte("Data to sign with Ed25519")

		// 签名.
		signature, err := operator.Sign(data)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		// 验签.
		if err := operator.Verify(data, signature); err != nil {
			t.Fatalf("verify failed: %v", err)
		}

		// 验证篡改后的数据应该失败.
		tamperedData := []byte("Tampered data")
		if err := operator.Verify(tamperedData, signature); err == nil {
			t.Error("verify should fail for tampered data")
		}
	})

	t.Run("HybridEncrypt_Decrypt", func(t *testing.T) {
		plaintext := []byte("Large data for Ed25519 hybrid encryption using X25519 key exchange.")

		// 混合加密.
		encrypted, nonce, err := operator.HybridEncrypt(plaintext)
		if err != nil {
			t.Fatalf("hybrid encrypt failed: %v", err)
		}
		if len(nonce) == 0 {
			t.Error("nonce should not be empty")
		}

		// 混合解密.
		decrypted, err := operator.HybridDecrypt(encrypted)
		if err != nil {
			t.Fatalf("hybrid decrypt failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("decrypted data mismatch")
		}
	})

	t.Run("HybridEncrypt_NilData", func(t *testing.T) {
		// 测试 nil 数据加密.
		encrypted, nonce, err := operator.HybridEncrypt(nil)
		if err != nil {
			t.Fatalf("hybrid encrypt nil data failed: %v", err)
		}

		// nonce 应该有效.
		if len(nonce) == 0 {
			t.Error("nonce should not be empty for nil data")
		}

		// 密文应该为 nil.
		if encrypted != nil {
			t.Errorf("encrypted should be nil for nil plaintext, got len=%d", len(encrypted))
		}
	})
}

func TestCertificateWithoutPrivateKey(t *testing.T) {
	// 生成 CA 证书.
	caCfg := &CACertConfig{
		DaysValid:    365,
		Subject:      Subject{CommonName: "Test CA"},
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
	}
	if err := GenCACert(caCfg); err != nil {
		t.Fatalf("gen ca cert failed: %v", err)
	}

	// 生成 RSA 证书.
	rsaCfg := &CASignedCertConfig{
		CACert:       caCfg.Cert,
		CAKey:        caCfg.Key,
		Name:         "rsa-test",
		Subject:      Subject{CommonName: "rsa-test"},
		DaysValid:    365,
		KeyAlgorithm: KeyAlgorithmRSA,
		RSAKeyBits:   2048,
		Usage:        UsageServer,
	}
	if err := GenerateCASignedCert(rsaCfg); err != nil {
		t.Fatalf("gen rsa cert failed: %v", err)
	}

	// 创建仅包含证书(无私钥)的对象.
	cert, err := NewCertificateFromCert(rsaCfg.Cert)
	if err != nil {
		t.Fatalf("new certificate failed: %v", err)
	}

	if cert.HasPrivateKey() {
		t.Error("certificate should not have private key")
	}

	operator, err := cert.GetCryptoOperator()
	if err != nil {
		t.Fatalf("get crypto operator failed: %v", err)
	}

	// 混合加密应该成功(只需要公钥).
	plaintext := []byte("Hello, this is test data for hybrid encryption")
	_, _, err = operator.HybridEncrypt(plaintext)
	if err != nil {
		t.Errorf("hybrid encrypt should succeed with public key only: %v", err)
	}

	// 混合解密应该失败(需要私钥).
	_, err = operator.HybridDecrypt([]byte{0, 0})
	if err != ErrNoPrivateKey {
		t.Errorf("hybrid decrypt should fail without private key, got: %v", err)
	}

	// 签名应该失败(需要私钥).
	_, err = operator.Sign([]byte("data"))
	if err != ErrNoPrivateKey {
		t.Errorf("sign should fail without private key, got: %v", err)
	}
}
