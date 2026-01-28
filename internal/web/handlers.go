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

	"github.com/jiaopengzi/go-utils/cert"
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
		req.Algorithm = "RSA"
	}

	if req.RSABits == 0 {
		req.RSABits = 2048
	}

	if req.ECDSACurve == "" {
		req.ECDSACurve = "P256"
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

	cfg := &cert.CACertConfig{
		KeyAlgorithm: cert.KeyAlgorithm(req.Algorithm),
		RSAKeyBits:   req.RSABits,
		ECDSACurve:   cert.ECDSACurve(req.ECDSACurve),
		DaysValid:    req.Days,
		MaxPathLen:   req.MaxPathLen,
		PathLenZero:  req.PathLenZero,
		Subject: cert.Subject{
			CommonName:   req.CommonName,
			Organization: req.Org,
			Country:      req.Country,
			State:        req.State,
			Locality:     req.Locality,
		},
	}

	if err := cert.GenCACert(cfg); err != nil {
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
		req.Algorithm = "RSA"
	}

	if req.RSABits == 0 {
		req.RSABits = 2048
	}

	if req.ECDSACurve == "" {
		req.ECDSACurve = "P256"
	}

	if req.Days == 0 {
		req.Days = 365
	}

	if req.CommonName == "" {
		req.CommonName = "localhost"
	}

	if req.Usage == "" {
		req.Usage = "server"
	}

	sanConfig := cert.ParseSANFromStr(req.DNSNames, req.IPAddrs)
	usage := parseUsage(req.Usage)

	cfg := &cert.CASignedCertConfig{
		CACert:       req.CACert,
		CAKey:        req.CAKey,
		Name:         req.CommonName,
		KeyAlgorithm: cert.KeyAlgorithm(req.Algorithm),
		RSAKeyBits:   req.RSABits,
		ECDSACurve:   cert.ECDSACurve(req.ECDSACurve),
		DaysValid:    req.Days,
		SAN:          sanConfig,
		Usage:        usage,
		IsCA:         req.IsCA,
		Subject: cert.Subject{
			CommonName:   req.CommonName,
			Organization: req.Org,
			Country:      req.Country,
		},
	}

	if err := cert.GenerateCASignedCert(cfg); err != nil {
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

	signature, err := cert.SignData(req.Key, []byte(req.Data))
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

	if err := cert.VerifySignature(req.Cert, []byte(req.Data), signature); err != nil {
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

	ciphertext, _, err := cert.EncryptWithCert(req.Cert, []byte(req.Data))
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

	plaintext, err := cert.DecryptWithKey(req.Cert, req.Key, ciphertext)
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

	var usage cert.CertUsage
	if req.Usage != "" {
		usage = parseUsage(req.Usage)
	}

	cfg := &cert.CertValidateConfig{
		Cert:            req.Cert,
		CACert:          req.CACert,
		IntermediateCAs: req.IntermediateCAs,
		DNSName:         req.DNSName,
		Usage:           usage,
	}

	if err := cert.ValidateCert(cfg); err != nil {
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

func parseUsage(usage string) cert.CertUsage {
	switch usage {
	case "server":
		return cert.UsageServer
	case "client":
		return cert.UsageClient
	case "codesigning":
		return cert.UsageCodeSigning
	case "email":
		return cert.UsageEmailProtection
	default:
		return cert.UsageServer
	}
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
	mux.HandleFunc("/api/sign", SignHandler)
	mux.HandleFunc("/api/verify", VerifyHandler)
	mux.HandleFunc("/api/encrypt", EncryptHandler)
	mux.HandleFunc("/api/decrypt", DecryptHandler)
	mux.HandleFunc("/api/validatechain", ValidateChainHandler)

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
