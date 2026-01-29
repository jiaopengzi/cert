//
// FilePath    : cert\internal\web\handlers.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : Web API 处理器
//

package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jiaopengzi/cert/core"
)

// 默认值常量
const (
	defaultAlgorithm  = "RSA"
	defaultECDSACurve = "P256"
	defaultUsage      = "server"
)

// Response 通用响应结构
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// writeJSON 写入 JSON 响应
func writeJSON(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "JSON encode failed", http.StatusInternalServerError)
	}
}

// VersionHandler 返回版本处理器
func VersionHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    map[string]string{"version": version},
		})
	}
}

// GenRootCARequest 生成根证书请求
type GenRootCARequest struct {
	Algorithm   string `json:"algorithm"`
	RSABits     int    `json:"rsaBits"`
	ECDSACurve  string `json:"ecdsaCurve"`
	Days        int    `json:"days"`
	CommonName  string `json:"commonName"`
	Org         string `json:"org"`
	Country     string `json:"country"`
	State       string `json:"state"`
	Locality    string `json:"locality"`
	MaxPathLen  int    `json:"maxPathLen"`
	PathLenZero bool   `json:"pathLenZero"`
}

// GenRootCAHandler 生成根证书处理器
func GenRootCAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req GenRootCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	// 设置默认值
	if req.Algorithm == "" {
		req.Algorithm = defaultAlgorithm
	}

	if req.RSABits == 0 {
		req.RSABits = 2048
	}

	if req.ECDSACurve == "" {
		req.ECDSACurve = defaultECDSACurve
	}

	if req.Days == 0 {
		req.Days = 3650
	}

	if req.CommonName == "" {
		req.CommonName = "Root CA"
	}

	if req.MaxPathLen == 0 {
		req.MaxPathLen = -1
	}

	cfg := &core.CACertConfig{
		KeyAlgorithm: core.KeyAlgorithm(req.Algorithm),
		RSAKeyBits:   req.RSABits,
		ECDSACurve:   core.ECDSACurve(req.ECDSACurve),
		DaysValid:    req.Days,
		MaxPathLen:   req.MaxPathLen,
		PathLenZero:  req.PathLenZero,
		Subject: core.Subject{
			CommonName:   req.CommonName,
			Organization: req.Org,
			Country:      req.Country,
			State:        req.State,
			Locality:     req.Locality,
		},
	}

	if err := core.GenCACert(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Generate root CA failed (生成根证书失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Root CA generated successfully (根证书生成成功)",
		Data: map[string]string{
			"cert": cfg.Cert,
			"key":  cfg.Key,
		},
	})
}

// SignCertRequest 签发证书请求
type SignCertRequest struct {
	CACert     string `json:"caCert"`
	CAKey      string `json:"caKey"`
	Algorithm  string `json:"algorithm"`
	RSABits    int    `json:"rsaBits"`
	ECDSACurve string `json:"ecdsaCurve"`
	Days       int    `json:"days"`
	CommonName string `json:"commonName"`
	Org        string `json:"org"`
	Country    string `json:"country"`
	DNSNames   string `json:"dnsNames"`
	IPAddrs    string `json:"ipAddrs"`
	Usage      string `json:"usage"`
	IsCA       bool   `json:"isCA"`
}

// SignCertHandler 签发证书处理器
func SignCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req SignCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	// 设置默认值
	if req.Algorithm == "" {
		req.Algorithm = defaultAlgorithm
	}

	if req.RSABits == 0 {
		req.RSABits = 2048
	}

	if req.ECDSACurve == "" {
		req.ECDSACurve = defaultECDSACurve
	}

	if req.Days == 0 {
		req.Days = 365
	}

	if req.CommonName == "" {
		req.CommonName = "localhost"
	}

	if req.Usage == "" {
		req.Usage = defaultUsage
	}

	sanConfig := core.ParseSANFromStr(req.DNSNames, req.IPAddrs)
	usage := parseUsage(req.Usage)

	cfg := &core.CASignedCertConfig{
		CACert:       req.CACert,
		CAKey:        req.CAKey,
		Name:         req.CommonName,
		KeyAlgorithm: core.KeyAlgorithm(req.Algorithm),
		RSAKeyBits:   req.RSABits,
		ECDSACurve:   core.ECDSACurve(req.ECDSACurve),
		DaysValid:    req.Days,
		SAN:          sanConfig,
		Usage:        usage,
		IsCA:         req.IsCA,
		Subject: core.Subject{
			CommonName:   req.CommonName,
			Organization: req.Org,
			Country:      req.Country,
		},
	}

	if err := core.GenerateCASignedCert(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Sign certificate failed (签发证书失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Certificate signed successfully (证书签发成功)",
		Data: map[string]string{
			"cert": cfg.Cert,
			"key":  cfg.Key,
		},
	})
}

// SignRequest 签名请求
type SignRequest struct {
	Key  string `json:"key"`
	Data string `json:"data"`
}

// SignHandler 签名处理器
func SignHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	signature, err := core.SignData(req.Key, []byte(req.Data))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Sign failed (签名失败: )" + err.Error(),
		})

		return
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Signed successfully (签名成功)",
		Data: map[string]string{
			"signature": signatureB64,
		},
	})
}

// VerifyRequest 验签请求
type VerifyRequest struct {
	Cert      string `json:"cert"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// VerifyHandler 验签处理器
func VerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Decode signature failed (解码签名失败: )" + err.Error(),
		})

		return
	}

	if err := core.VerifySignature(req.Cert, []byte(req.Data), signature); err != nil {
		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data: map[string]interface{}{
				"valid":  false,
				"reason": err.Error(),
			},
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Signature verified successfully (签名验证成功)",
		Data: map[string]interface{}{
			"valid": true,
		},
	})
}

// EncryptRequest 加密请求
type EncryptRequest struct {
	Cert string `json:"cert"`
	Data string `json:"data"`
}

// EncryptHandler 加密处理器
func EncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	ciphertext, _, err := core.EncryptWithCert(req.Cert, []byte(req.Data))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Encrypt failed (加密失败: )" + err.Error(),
		})

		return
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Encrypted successfully (加密成功)",
		Data: map[string]string{
			"ciphertext": ciphertextB64,
		},
	})
}

// DecryptRequest 解密请求
type DecryptRequest struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	Data string `json:"data"`
}

// DecryptHandler 解密处理器
func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Decode ciphertext failed (解码密文失败: )" + err.Error(),
		})

		return
	}

	plaintext, err := core.DecryptWithKey(req.Cert, req.Key, ciphertext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Decrypt failed (解密失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Decrypted successfully (解密成功)",
		Data: map[string]string{
			"plaintext": string(plaintext),
		},
	})
}

// ValidateChainRequest 验证证书链请求
type ValidateChainRequest struct {
	CACert          string   `json:"caCert"`
	Cert            string   `json:"cert"`
	IntermediateCAs []string `json:"intermediateCAs"`
	DNSName         string   `json:"dnsName"`
	Usage           string   `json:"usage"`
}

// ValidateChainHandler 验证证书链处理器
func ValidateChainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req ValidateChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	var usage core.CertUsage
	if req.Usage != "" {
		usage = parseUsage(req.Usage)
	}

	cfg := &core.CertValidateConfig{
		Cert:            req.Cert,
		CACert:          req.CACert,
		IntermediateCAs: req.IntermediateCAs,
		DNSName:         req.DNSName,
		Usage:           usage,
	}

	if err := core.ValidateCert(cfg); err != nil {
		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data: map[string]interface{}{
				"valid":  false,
				"reason": err.Error(),
			},
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Certificate chain validated successfully (证书链验证成功)",
		Data: map[string]interface{}{
			"valid": true,
		},
	})
}

func parseUsage(usage string) core.CertUsage {
	switch usage {
	case "server":
		return core.UsageServer
	case "client":
		return core.UsageClient
	case "codesigning":
		return core.UsageCodeSigning
	case "email":
		return core.UsageEmailProtection
	default:
		return core.UsageServer
	}
}

// CertInfoRequest 查看证书信息请求
type CertInfoRequest struct {
	Cert string `json:"cert"`
}

// CertInfoHandler 查看证书信息处理器
func CertInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req CertInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	info, err := core.GetCertInfo(req.Cert)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Parse certificate failed (解析证书失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Certificate info retrieved successfully (证书信息获取成功)",
		Data: map[string]interface{}{
			"serialNumber": info.SerialNumber,
			"subject":      info.Subject,
			"issuer":       info.Issuer,
			"notBefore":    info.NotBefore.Format("2006-01-02 15:04:05"),
			"notAfter":     info.NotAfter.Format("2006-01-02 15:04:05"),
			"isCA":         info.IsCA,
			"keyAlgorithm": info.KeyAlgorithm,
			"dnsNames":     info.DNSNames,
			"ipAddresses":  info.IPAddresses,
			"extKeyUsages": info.ExtKeyUsages,
		},
	})
}

// GenCSRRequest 生成 CSR 请求
type GenCSRRequest struct {
	Algorithm  string `json:"algorithm"`
	RSABits    int    `json:"rsaBits"`
	ECDSACurve string `json:"ecdsaCurve"`
	CommonName string `json:"commonName"`
	Org        string `json:"org"`
	Country    string `json:"country"`
	State      string `json:"state"`
	Locality   string `json:"locality"`
	DNSNames   string `json:"dnsNames"`
	IPAddrs    string `json:"ipAddrs"`
}

// GenCSRHandler 生成 CSR 处理器
func GenCSRHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req GenCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	// 设置默认值
	if req.Algorithm == "" {
		req.Algorithm = defaultAlgorithm
	}

	if req.RSABits == 0 {
		req.RSABits = 2048
	}

	if req.ECDSACurve == "" {
		req.ECDSACurve = defaultECDSACurve
	}

	if req.CommonName == "" {
		req.CommonName = "localhost"
	}

	sanConfig := core.ParseSANFromStr(req.DNSNames, req.IPAddrs)

	cfg := &core.CSRConfig{
		KeyAlgorithm: core.KeyAlgorithm(req.Algorithm),
		RSAKeyBits:   req.RSABits,
		ECDSACurve:   core.ECDSACurve(req.ECDSACurve),
		SAN:          sanConfig,
		Subject: core.Subject{
			CommonName:   req.CommonName,
			Organization: req.Org,
			Country:      req.Country,
			State:        req.State,
			Locality:     req.Locality,
		},
	}

	if err := core.GenerateCSR(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Generate CSR failed (生成 CSR 失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "CSR generated successfully (CSR 生成成功)",
		Data: map[string]string{
			"csr": cfg.CSR,
			"key": cfg.Key,
		},
	})
}

// SignCSRRequest 签发 CSR 请求
type SignCSRRequest struct {
	CACert string `json:"caCert"`
	CAKey  string `json:"caKey"`
	CSR    string `json:"csr"`
	Days   int    `json:"days"`
	Usage  string `json:"usage"`
	IsCA   bool   `json:"isCA"`
}

// SignCSRHandler 签发 CSR 处理器
func SignCSRHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req SignCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	// 设置默认值
	if req.Days == 0 {
		req.Days = 365
	}

	if req.Usage == "" {
		req.Usage = defaultUsage
	}

	usage := parseUsage(req.Usage)

	cfg := &core.CSRSignConfig{
		CACert:    req.CACert,
		CAKey:     req.CAKey,
		CSR:       req.CSR,
		DaysValid: req.Days,
		Usage:     usage,
		IsCA:      req.IsCA,
	}

	if err := core.SignCSR(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Sign CSR failed (签发 CSR 失败: )" + err.Error(),
		})

		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "CSR signed successfully (CSR 签发成功)",
		Data: map[string]string{
			"cert": cfg.Cert,
		},
	})
}

// GenCRLRequest 生成 CRL 请求
type GenCRLRequest struct {
	CACert         string   `json:"caCert"`
	CAKey          string   `json:"caKey"`
	RevokedCerts   []string `json:"revokedCerts"`
	ExistingCRL    string   `json:"existingCRL"`
	SkipExpired    bool     `json:"skipExpired"`
	PruneAfterDays int      `json:"pruneAfterDays"`
	Days           int      `json:"days"`
}

// GenCRLHandler 生成 CRL 处理器
func GenCRLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req GenCRLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	// 设置默认值
	if req.Days == 0 {
		req.Days = 30
	}

	cfg := &core.CRLConfig{
		CACert:         req.CACert,
		CAKey:          req.CAKey,
		RevokedCerts:   req.RevokedCerts,
		ExistingCRL:    req.ExistingCRL,
		SkipExpired:    req.SkipExpired,
		PruneAfterDays: req.PruneAfterDays,
		DaysValid:      req.Days,
	}

	if err := core.GenerateCRL(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Generate CRL failed (生成 CRL 失败: )" + err.Error(),
		})

		return
	}

	// 收集已吊销的序列号
	var revokedSerials []string
	for _, serial := range cfg.RevokedSerials {
		revokedSerials = append(revokedSerials, serial.String())
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "CRL generated successfully (CRL 生成成功)",
		Data: map[string]interface{}{
			"crl":            cfg.CRL,
			"thisUpdate":     cfg.ThisUpdate.Format("2006-01-02 15:04:05"),
			"nextUpdate":     cfg.NextUpdate.Format("2006-01-02 15:04:05"),
			"revokedSerials": revokedSerials,
			"skippedExpired": cfg.SkippedExpired,
			"prunedCount":    cfg.PrunedCount,
		},
	})
}

// ViewCRLRequest 查看 CRL 请求
type ViewCRLRequest struct {
	CRL string `json:"crl"`
}

// ViewCRLHandler 查看 CRL 处理器
func ViewCRLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req ViewCRLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	revokedCerts, err := core.ParseCRL(req.CRL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Parse CRL failed (解析 CRL 失败: )" + err.Error(),
		})

		return
	}

	// 转换为 JSON 友好的格式
	var certList []map[string]interface{}
	for _, cert := range revokedCerts {
		certList = append(certList, map[string]interface{}{
			"serialNumber":   cert.SerialNumber.String(),
			"revocationTime": cert.RevocationTime.Format("2006-01-02 15:04:05"),
			"reason":         cert.Reason,
		})
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "CRL parsed successfully (CRL 解析成功)",
		Data: map[string]interface{}{
			"revokedCount": len(revokedCerts),
			"revokedCerts": certList,
		},
	})
}

// CheckRevokedRequest 检查证书吊销状态请求
type CheckRevokedRequest struct {
	Cert string `json:"cert"`
	CRL  string `json:"crl"`
}

// CheckRevokedHandler 检查证书吊销状态处理器
func CheckRevokedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed (方法不允许)",
		})

		return
	}

	var req CheckRevokedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request (无效的请求: )" + err.Error(),
		})

		return
	}

	revoked, err := core.IsCertRevoked(req.Cert, req.CRL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Check revocation failed (检查吊销状态失败: )" + err.Error(),
		})

		return
	}

	// 获取证书信息
	var serialNumber string
	if info, infoErr := core.GetCertInfo(req.Cert); infoErr == nil {
		serialNumber = info.SerialNumber
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Revocation check completed (吊销状态检查完成)",
		Data: map[string]interface{}{
			"revoked":      revoked,
			"serialNumber": serialNumber,
		},
	})
}

// StartServer 启动 Web 服务器
func StartServer(host string, port int, staticDir, version string) error {
	// 注册路由
	mux := http.NewServeMux()

	// 静态文件服务（从外部目录）
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	// API 路由
	mux.HandleFunc("/api/version", VersionHandler(version))
	mux.HandleFunc("/api/genrootca", GenRootCAHandler)
	mux.HandleFunc("/api/signcert", SignCertHandler)
	mux.HandleFunc("/api/certinfo", CertInfoHandler)
	mux.HandleFunc("/api/sign", SignHandler)
	mux.HandleFunc("/api/verify", VerifyHandler)
	mux.HandleFunc("/api/encrypt", EncryptHandler)
	mux.HandleFunc("/api/decrypt", DecryptHandler)
	mux.HandleFunc("/api/validatechain", ValidateChainHandler)
	mux.HandleFunc("/api/gencsr", GenCSRHandler)
	mux.HandleFunc("/api/signcsr", SignCSRHandler)
	mux.HandleFunc("/api/gencrl", GenCRLHandler)
	mux.HandleFunc("/api/viewcrl", ViewCRLHandler)
	mux.HandleFunc("/api/checkrevoked", CheckRevokedHandler)

	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("Certificate Tool Web Server (证书工具 Web 服务)\n")
	fmt.Printf("Version (版本: %s)\n", version)
	fmt.Printf("Static files (静态文件目录: %s)\n", staticDir)
	fmt.Printf("Listening on (监听地址: http://%s)\n", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return server.ListenAndServe()
}
