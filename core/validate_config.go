//
// FilePath    : cert\core\validate_config.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 配置验证功能
//

package core

import "errors"

// 配置验证错误定义.
var (
	ErrDaysValidRequired    = errors.New("days valid is required and must be > 0")
	ErrKeyAlgorithmRequired = errors.New("key algorithm is required")
	ErrRSAKeyBitsRequired   = errors.New("RSA key bits is required when using RSA algorithm")
	ErrECDSACurveRequired   = errors.New("ECDSA curve is required when using ECDSA algorithm")
	ErrNameRequired         = errors.New("name is required")
	ErrCACertRequired       = errors.New("CA certificate is required")
	ErrCAKeyRequired        = errors.New("CA private key is required")
	ErrCSRRequired          = errors.New("CSR is required")
	ErrCertRequired         = errors.New("certificate is required")
	ErrPrivateKeyRequired   = errors.New("private key is required")
	ErrRevokedCertsRequired = errors.New("revoked certificates list is required")
)

// validateDaysValid 验证有效期天数.
func validateDaysValid(days int) error {
	if days <= 0 {
		return ErrDaysValidRequired
	}

	return nil
}

// validateKeyAlgorithm 验证密钥算法.
func validateKeyAlgorithm(algo KeyAlgorithm) error {
	if algo == "" {
		return ErrKeyAlgorithmRequired
	}

	return nil
}

// validateRSAKeyBits 验证 RSA 密钥位数(仅当算法为 RSA 时).
func validateRSAKeyBits(algo KeyAlgorithm, bits int) error {
	if algo == KeyAlgorithmRSA && bits == 0 {
		return ErrRSAKeyBitsRequired
	}

	return nil
}

// validateECDSACurve 验证 ECDSA 曲线(仅当算法为 ECDSA 时).
func validateECDSACurve(algo KeyAlgorithm, curve ECDSACurve) error {
	if algo == KeyAlgorithmECDSA && curve == "" {
		return ErrECDSACurveRequired
	}

	return nil
}

// validateName 验证名称.
func validateName(name string) error {
	if name == "" {
		return ErrNameRequired
	}

	return nil
}

// validateCACert 验证 CA 证书.
func validateCACert(caCert string) error {
	if caCert == "" {
		return ErrCACertRequired
	}

	return nil
}

// validateCAKey 验证 CA 私钥.
func validateCAKey(caKey string) error {
	if caKey == "" {
		return ErrCAKeyRequired
	}

	return nil
}

// validateCSR 验证 CSR.
func validateCSR(csr string) error {
	if csr == "" {
		return ErrCSRRequired
	}

	return nil
}

// ValidateCACertConfig 验证 CA 证书配置.
func ValidateCACertConfig(cfg *CACertConfig) error {
	if err := validateDaysValid(cfg.DaysValid); err != nil {
		return err
	}

	if err := validateKeyAlgorithm(cfg.KeyAlgorithm); err != nil {
		return err
	}

	if err := validateRSAKeyBits(cfg.KeyAlgorithm, cfg.RSAKeyBits); err != nil {
		return err
	}

	if err := validateECDSACurve(cfg.KeyAlgorithm, cfg.ECDSACurve); err != nil {
		return err
	}

	return nil
}

// ValidateCASignedCertConfig 验证 CA 签发证书配置.
func ValidateCASignedCertConfig(cfg *CASignedCertConfig) error {
	if err := validateDaysValid(cfg.DaysValid); err != nil {
		return err
	}

	if err := validateName(cfg.Name); err != nil {
		return err
	}

	if err := validateCACert(cfg.CACert); err != nil {
		return err
	}

	if err := validateCAKey(cfg.CAKey); err != nil {
		return err
	}

	if err := validateKeyAlgorithm(cfg.KeyAlgorithm); err != nil {
		return err
	}

	if err := validateRSAKeyBits(cfg.KeyAlgorithm, cfg.RSAKeyBits); err != nil {
		return err
	}

	if err := validateECDSACurve(cfg.KeyAlgorithm, cfg.ECDSACurve); err != nil {
		return err
	}

	return nil
}

// ValidateCSRConfig 验证 CSR 配置.
func ValidateCSRConfig(cfg *CSRConfig) error {
	if err := validateKeyAlgorithm(cfg.KeyAlgorithm); err != nil {
		return err
	}

	if err := validateRSAKeyBits(cfg.KeyAlgorithm, cfg.RSAKeyBits); err != nil {
		return err
	}

	if err := validateECDSACurve(cfg.KeyAlgorithm, cfg.ECDSACurve); err != nil {
		return err
	}

	return nil
}

// ValidateCSRSignConfig 验证 CSR 签发配置.
func ValidateCSRSignConfig(cfg *CSRSignConfig) error {
	if err := validateDaysValid(cfg.DaysValid); err != nil {
		return err
	}

	if err := validateCACert(cfg.CACert); err != nil {
		return err
	}

	if err := validateCAKey(cfg.CAKey); err != nil {
		return err
	}

	if err := validateCSR(cfg.CSR); err != nil {
		return err
	}

	return nil
}

// ValidateCRLConfig 验证 CRL 配置.
func ValidateCRLConfig(cfg *CRLConfig) error {
	if err := validateDaysValid(cfg.DaysValid); err != nil {
		return err
	}

	if err := validateCACert(cfg.CACert); err != nil {
		return err
	}

	if err := validateCAKey(cfg.CAKey); err != nil {
		return err
	}

	return nil
}
