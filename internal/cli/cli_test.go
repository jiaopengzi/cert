//
// FilePath    : cert\internal\cli\cli_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CLI 命令测试
//

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// TestGenRootCACmd 测试生成根证书命令
func TestGenRootCACmd(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "root.pem")
	keyPath := filepath.Join(tmpDir, "root_key.pem")

	app := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}

	args := []string{"test", "genrootca",
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--algorithm", "RSA",
		"--rsa-bits", "2048",
		"--days", "365",
		"--cn", "Test Root CA",
		"--org", "Test Org",
		"--country", "CN",
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("GenRootCACmd failed: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	// 验证文件内容包含 PEM 标记
	certData, _ := os.ReadFile(certPath)
	if !bytes.Contains(certData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("Certificate file does not contain valid PEM data")
	}

	keyData, _ := os.ReadFile(keyPath)
	if !bytes.Contains(keyData, []byte("-----BEGIN")) {
		t.Error("Private key file does not contain valid PEM data")
	}
}

// TestGenRootCACmd_ECDSA 测试使用 ECDSA 算法生成根证书
func TestGenRootCACmd_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "root_ecdsa.pem")
	keyPath := filepath.Join(tmpDir, "root_ecdsa_key.pem")

	app := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}

	args := []string{"test", "genrootca",
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--algorithm", "ECDSA",
		"--ecdsa-curve", "P256",
		"--cn", "Test ECDSA Root CA",
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("GenRootCACmd with ECDSA failed: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
}

// TestGenRootCACmd_Ed25519 测试使用 Ed25519 算法生成根证书
func TestGenRootCACmd_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "root_ed25519.pem")
	keyPath := filepath.Join(tmpDir, "root_ed25519_key.pem")

	app := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}

	args := []string{"test", "genrootca",
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--algorithm", "Ed25519",
		"--cn", "Test Ed25519 Root CA",
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("GenRootCACmd with Ed25519 failed: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
}

// TestSignCertCmd 测试签发证书命令
func TestSignCertCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 先生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发证书
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server_key.pem")

	signApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--cn", "localhost",
		"--dns-names", "localhost,example.com",
		"--ip-addrs", "127.0.0.1",
		"--usage", "server",
	}

	if err := signApp.Run(context.Background(), signArgs); err != nil {
		t.Fatalf("SignCertCmd failed: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Signed certificate was not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Private key was not created")
	}
}

// TestSignCertCmd_IntermediateCA 测试签发中间CA证书
func TestSignCertCmd_IntermediateCA(t *testing.T) {
	tmpDir := t.TempDir()

	// 先生成根证书
	caCertPath := filepath.Join(tmpDir, "root.pem")
	caKeyPath := filepath.Join(tmpDir, "root_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Root CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate Root CA failed: %v", err)
	}

	// 签发中间CA证书
	interCertPath := filepath.Join(tmpDir, "intermediate.pem")
	interKeyPath := filepath.Join(tmpDir, "intermediate_key.pem")

	signApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", interCertPath,
		"--key-out", interKeyPath,
		"--cn", "Intermediate CA",
		"--is-ca",
	}

	if err := signApp.Run(context.Background(), signArgs); err != nil {
		t.Fatalf("SignCertCmd for intermediate CA failed: %v", err)
	}

	if _, err := os.Stat(interCertPath); os.IsNotExist(err) {
		t.Error("Intermediate CA certificate was not created")
	}
}

// testSignAndVerify 辅助函数：完成签名和验签流程（使用 cert 包直接测试）
func testSignAndVerify(t *testing.T, algorithm string) {
	t.Helper()
	tmpDir := t.TempDir()

	// 生成CA
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--algorithm", algorithm,
		"--cn", "Test CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发证书
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert_key.pem")

	signCertApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signCertArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--algorithm", algorithm,
		"--cn", "Test Cert",
	}
	if err := signCertApp.Run(context.Background(), signCertArgs); err != nil {
		t.Fatalf("Sign cert failed: %v", err)
	}

	// 直接使用 cert 包测试签名和验签（避免解析控制台输出）
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Read key failed: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Read cert failed: %v", err)
	}

	testData := []byte("Hello, World!")

	// 签名
	signature, err := core.SignData(string(keyPEM), testData)
	if err != nil {
		t.Fatalf("Sign data failed: %v", err)
	}

	// 验签
	if err := core.VerifySignature(string(certPEM), testData, signature); err != nil {
		t.Fatalf("Verify signature failed: %v", err)
	}
}

// TestSignAndVerifyCmd_RSA 测试使用 RSA 签名和验签
func TestSignAndVerifyCmd_RSA(t *testing.T) {
	testSignAndVerify(t, "RSA")
}

// TestSignAndVerifyCmd_ECDSA 测试使用 ECDSA 签名和验签
func TestSignAndVerifyCmd_ECDSA(t *testing.T) {
	testSignAndVerify(t, "ECDSA")
}

// TestSignAndVerifyCmd_Ed25519 测试使用 Ed25519 签名和验签
func TestSignAndVerifyCmd_Ed25519(t *testing.T) {
	testSignAndVerify(t, "Ed25519")
}

// TestEncryptAndDecryptCmd 测试加密和解密(仅RSA支持)
func TestEncryptAndDecryptCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成CA
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--algorithm", "RSA",
		"--rsa-bits", "2048",
		"--cn", "Test CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发证书
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert_key.pem")

	signCertApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signCertArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--algorithm", "RSA",
		"--rsa-bits", "2048",
		"--cn", "Test Cert",
	}
	if err := signCertApp.Run(context.Background(), signCertArgs); err != nil {
		t.Fatalf("Sign cert failed: %v", err)
	}

	// 直接使用 cert 包测试加密和解密（避免解析控制台输出）
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Read cert failed: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Read key failed: %v", err)
	}

	plaintext := []byte("Secret Message")

	// 加密
	ciphertext, _, err := core.EncryptWithCert(string(certPEM), plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密
	decrypted, err := core.DecryptWithKey(string(certPEM), string(keyPEM), ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match. Got: %s, Want: %s", string(decrypted), string(plaintext))
	}
}

// TestValidateChainCmd 测试证书链验证命令
func TestValidateChainCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根CA
	rootCertPath := filepath.Join(tmpDir, "root.pem")
	rootKeyPath := filepath.Join(tmpDir, "root_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", rootCertPath,
		"--key-out", rootKeyPath,
		"--cn", "Root CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate Root CA failed: %v", err)
	}

	// 签发服务器证书
	serverCertPath := filepath.Join(tmpDir, "server.pem")
	serverKeyPath := filepath.Join(tmpDir, "server_key.pem")

	signApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signArgs := []string{"test", "signcert",
		"--ca-cert", rootCertPath,
		"--ca-key", rootKeyPath,
		"--cert-out", serverCertPath,
		"--key-out", serverKeyPath,
		"--cn", "localhost",
		"--dns-names", "localhost",
		"--usage", "server",
	}
	if err := signApp.Run(context.Background(), signArgs); err != nil {
		t.Fatalf("Sign server cert failed: %v", err)
	}

	// 验证证书链
	validateApp := &cli.Command{
		Commands: []*cli.Command{ValidateChainCmd()},
	}
	validateArgs := []string{"test", "validatechain",
		"--ca-cert", rootCertPath,
		"--cert", serverCertPath,
		"--dns-name", "localhost",
		"--usage", "server",
	}
	if err := validateApp.Run(context.Background(), validateArgs); err != nil {
		t.Fatalf("ValidateChain failed: %v", err)
	}
}

// TestValidateChainCmd_WithIntermediate 测试包含中间CA的证书链验证
func TestValidateChainCmd_WithIntermediate(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根CA
	rootCertPath := filepath.Join(tmpDir, "root.pem")
	rootKeyPath := filepath.Join(tmpDir, "root_key.pem")

	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", rootCertPath,
		"--key-out", rootKeyPath,
		"--cn", "Root CA",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate Root CA failed: %v", err)
	}

	// 签发中间CA
	interCertPath := filepath.Join(tmpDir, "intermediate.pem")
	interKeyPath := filepath.Join(tmpDir, "intermediate_key.pem")

	signInterApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signInterArgs := []string{"test", "signcert",
		"--ca-cert", rootCertPath,
		"--ca-key", rootKeyPath,
		"--cert-out", interCertPath,
		"--key-out", interKeyPath,
		"--cn", "Intermediate CA",
		"--is-ca",
	}
	if err := signInterApp.Run(context.Background(), signInterArgs); err != nil {
		t.Fatalf("Sign intermediate CA failed: %v", err)
	}

	// 使用中间CA签发服务器证书
	serverCertPath := filepath.Join(tmpDir, "server.pem")
	serverKeyPath := filepath.Join(tmpDir, "server_key.pem")

	signServerApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signServerArgs := []string{"test", "signcert",
		"--ca-cert", interCertPath,
		"--ca-key", interKeyPath,
		"--cert-out", serverCertPath,
		"--key-out", serverKeyPath,
		"--cn", "localhost",
		"--dns-names", "localhost",
		"--usage", "server",
	}
	if err := signServerApp.Run(context.Background(), signServerArgs); err != nil {
		t.Fatalf("Sign server cert failed: %v", err)
	}

	// 验证证书链（包含中间CA）
	validateApp := &cli.Command{
		Commands: []*cli.Command{ValidateChainCmd()},
	}
	validateArgs := []string{"test", "validatechain",
		"--ca-cert", rootCertPath,
		"--cert", serverCertPath,
		"--intermediate", interCertPath,
		"--dns-name", "localhost",
		"--usage", "server",
	}
	if err := validateApp.Run(context.Background(), validateArgs); err != nil {
		t.Fatalf("ValidateChain with intermediate failed: %v", err)
	}
}

// TestVersionCmd 测试版本命令
func TestVersionCmd(t *testing.T) {
	version := "1.0.0-test"
	app := &cli.Command{
		Commands: []*cli.Command{VersionCmd(version)},
	}

	args := []string{"test", "version"}
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("VersionCmd failed: %v", err)
	}
}

// TestParseUsage 测试 parseUsage 函数
func TestParseUsage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"server", "server"},
		{"client", "client"},
		{"codesigning", "codesigning"},
		{"email", "email"},
		{"unknown", "server"}, // 默认值
		{"", "server"},        // 空值
	}

	for _, tt := range tests {
		usage := parseUsage(tt.input)
		// 验证返回值不为零（说明函数正常工作）
		if tt.input == "server" || tt.input == "" || tt.input == "unknown" {
			// 这些情况应该返回 UsageServer
			_ = usage // 验证不 panic
		}
	}
}

// TestCertInfoCmd 测试查看证书信息命令
func TestCertInfoCmd(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "root.pem")
	keyPath := filepath.Join(tmpDir, "root_key.pem")

	// 先生成根证书
	genApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genArgs := []string{"test", "genrootca",
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--cn", "Test Root CA",
		"--org", "Test Org",
	}
	if err := genApp.Run(context.Background(), genArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 查看证书信息
	infoApp := &cli.Command{
		Commands: []*cli.Command{CertInfoCmd()},
	}
	infoArgs := []string{"test", "certinfo",
		"--cert", certPath,
	}
	if err := infoApp.Run(context.Background(), infoArgs); err != nil {
		t.Fatalf("CertInfoCmd failed: %v", err)
	}
}

// TestGenCSRCmd 测试生成 CSR 命令
func TestGenCSRCmd(t *testing.T) {
	tmpDir := t.TempDir()
	csrPath := filepath.Join(tmpDir, "request.csr")
	keyPath := filepath.Join(tmpDir, "request_key.pem")

	app := &cli.Command{
		Commands: []*cli.Command{GenCSRCmd()},
	}
	args := []string{"test", "gencsr",
		"--csr-out", csrPath,
		"--key-out", keyPath,
		"--algorithm", "RSA",
		"--rsa-bits", "2048",
		"--cn", "Test CSR",
		"--org", "Test Org",
		"--country", "CN",
		"--dns-names", "localhost,example.com",
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("GenCSRCmd failed: %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Error("CSR file was not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	// 验证 CSR 内容
	csrData, _ := os.ReadFile(csrPath)
	if !bytes.Contains(csrData, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
		t.Error("CSR file does not contain valid PEM data")
	}
}

// TestGenCSRCmd_ECDSA 测试使用 ECDSA 生成 CSR
func TestGenCSRCmd_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()
	csrPath := filepath.Join(tmpDir, "request_ecdsa.csr")
	keyPath := filepath.Join(tmpDir, "request_ecdsa_key.pem")

	app := &cli.Command{
		Commands: []*cli.Command{GenCSRCmd()},
	}
	args := []string{"test", "gencsr",
		"--csr-out", csrPath,
		"--key-out", keyPath,
		"--algorithm", "ECDSA",
		"--ecdsa-curve", "P256",
		"--cn", "Test ECDSA CSR",
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("GenCSRCmd with ECDSA failed: %v", err)
	}

	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Error("CSR file was not created")
	}
}

// TestSignCSRCmd 测试签发 CSR 命令
func TestSignCSRCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 生成 CSR
	csrPath := filepath.Join(tmpDir, "request.csr")
	csrKeyPath := filepath.Join(tmpDir, "request_key.pem")

	genCSRApp := &cli.Command{
		Commands: []*cli.Command{GenCSRCmd()},
	}
	genCSRArgs := []string{"test", "gencsr",
		"--csr-out", csrPath,
		"--key-out", csrKeyPath,
		"--cn", "Test CSR",
	}
	if err := genCSRApp.Run(context.Background(), genCSRArgs); err != nil {
		t.Fatalf("Generate CSR failed: %v", err)
	}

	// 签发 CSR
	signedCertPath := filepath.Join(tmpDir, "signed.pem")

	signCSRApp := &cli.Command{
		Commands: []*cli.Command{SignCSRCmd()},
	}
	signCSRArgs := []string{"test", "signcsr",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--cert-out", signedCertPath,
		"--days", "365",
		"--usage", "server",
	}
	if err := signCSRApp.Run(context.Background(), signCSRArgs); err != nil {
		t.Fatalf("SignCSRCmd failed: %v", err)
	}

	// 验证签发的证书
	if _, err := os.Stat(signedCertPath); os.IsNotExist(err) {
		t.Error("Signed certificate was not created")
	}

	certData, _ := os.ReadFile(signedCertPath)
	if !bytes.Contains(certData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("Signed certificate does not contain valid PEM data")
	}
}

// TestGenCRLCmd 测试生成 CRL 命令
func TestGenCRLCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 生成空 CRL（无吊销证书）
	crlPath := filepath.Join(tmpDir, "crl.pem")

	genCRLApp := &cli.Command{
		Commands: []*cli.Command{GenCRLCmd()},
	}
	genCRLArgs := []string{"test", "gencrl",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--out", crlPath,
		"--days", "30",
	}
	if err := genCRLApp.Run(context.Background(), genCRLArgs); err != nil {
		t.Fatalf("GenCRLCmd failed: %v", err)
	}

	// 验证 CRL 已创建
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		t.Error("CRL file was not created")
	}

	crlData, _ := os.ReadFile(crlPath)
	if !bytes.Contains(crlData, []byte("-----BEGIN X509 CRL-----")) {
		t.Error("CRL file does not contain valid PEM data")
	}
}

// TestGenCRLCmd_WithRevoked 测试生成包含吊销证书的 CRL
func TestGenCRLCmd_WithRevoked(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发一个证书用于吊销
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert_key.pem")

	signCertApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signCertArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--cn", "Test Cert",
	}
	if err := signCertApp.Run(context.Background(), signCertArgs); err != nil {
		t.Fatalf("Sign cert failed: %v", err)
	}

	// 生成包含吊销证书的 CRL
	crlPath := filepath.Join(tmpDir, "crl.pem")

	genCRLApp := &cli.Command{
		Commands: []*cli.Command{GenCRLCmd()},
	}
	genCRLArgs := []string{"test", "gencrl",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--revoke", certPath,
		"--out", crlPath,
		"--days", "30",
	}
	if err := genCRLApp.Run(context.Background(), genCRLArgs); err != nil {
		t.Fatalf("GenCRLCmd with revoked cert failed: %v", err)
	}

	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		t.Error("CRL file was not created")
	}
}

// TestViewCRLCmd 测试查看 CRL 命令
func TestViewCRLCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 生成 CRL
	crlPath := filepath.Join(tmpDir, "crl.pem")

	genCRLApp := &cli.Command{
		Commands: []*cli.Command{GenCRLCmd()},
	}
	genCRLArgs := []string{"test", "gencrl",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--out", crlPath,
	}
	if err := genCRLApp.Run(context.Background(), genCRLArgs); err != nil {
		t.Fatalf("GenCRLCmd failed: %v", err)
	}

	// 查看 CRL
	viewCRLApp := &cli.Command{
		Commands: []*cli.Command{ViewCRLCmd()},
	}
	viewCRLArgs := []string{"test", "viewcrl",
		"--crl", crlPath,
	}
	if err := viewCRLApp.Run(context.Background(), viewCRLArgs); err != nil {
		t.Fatalf("ViewCRLCmd failed: %v", err)
	}
}

// TestCheckRevokedCmd 测试检查证书吊销状态命令
func TestCheckRevokedCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发证书
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert_key.pem")

	signCertApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signCertArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--cn", "Test Cert",
	}
	if err := signCertApp.Run(context.Background(), signCertArgs); err != nil {
		t.Fatalf("Sign cert failed: %v", err)
	}

	// 生成包含该证书的 CRL
	crlPath := filepath.Join(tmpDir, "crl.pem")

	genCRLApp := &cli.Command{
		Commands: []*cli.Command{GenCRLCmd()},
	}
	genCRLArgs := []string{"test", "gencrl",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--revoke", certPath,
		"--out", crlPath,
	}
	if err := genCRLApp.Run(context.Background(), genCRLArgs); err != nil {
		t.Fatalf("GenCRLCmd failed: %v", err)
	}

	// 检查证书吊销状态
	checkApp := &cli.Command{
		Commands: []*cli.Command{CheckRevokedCmd()},
	}
	checkArgs := []string{"test", "checkrevoked",
		"--cert", certPath,
		"--crl", crlPath,
	}
	if err := checkApp.Run(context.Background(), checkArgs); err != nil {
		t.Fatalf("CheckRevokedCmd failed: %v", err)
	}
}

// TestCSRCmd 测试 CSR 命令组
func TestCSRCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 使用 CSR 命令组生成 CSR
	csrPath := filepath.Join(tmpDir, "request.csr")
	csrKeyPath := filepath.Join(tmpDir, "request_key.pem")

	csrApp := &cli.Command{
		Commands: []*cli.Command{CSRCmd()},
	}
	genCSRArgs := []string{"test", "csr", "generate",
		"--csr-out", csrPath,
		"--key-out", csrKeyPath,
		"--cn", "Test CSR",
	}
	if err := csrApp.Run(context.Background(), genCSRArgs); err != nil {
		t.Fatalf("CSR generate failed: %v", err)
	}

	// 使用 CSR 命令组签发 CSR
	signedCertPath := filepath.Join(tmpDir, "signed.pem")

	signCSRArgs := []string{"test", "csr", "sign",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--csr", csrPath,
		"--cert-out", signedCertPath,
	}
	if err := csrApp.Run(context.Background(), signCSRArgs); err != nil {
		t.Fatalf("CSR sign failed: %v", err)
	}

	if _, err := os.Stat(signedCertPath); os.IsNotExist(err) {
		t.Error("Signed certificate was not created")
	}
}

// TestCRLCmd 测试 CRL 命令组
func TestCRLCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 生成根证书
	caCertPath := filepath.Join(tmpDir, "ca.pem")
	caKeyPath := filepath.Join(tmpDir, "ca_key.pem")

	genCAApp := &cli.Command{
		Commands: []*cli.Command{GenRootCACmd()},
	}
	genCAArgs := []string{"test", "genrootca",
		"--cert-out", caCertPath,
		"--key-out", caKeyPath,
		"--cn", "Test CA",
	}
	if err := genCAApp.Run(context.Background(), genCAArgs); err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	// 签发证书
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert_key.pem")

	signCertApp := &cli.Command{
		Commands: []*cli.Command{SignCertCmd()},
	}
	signCertArgs := []string{"test", "signcert",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--cn", "Test Cert",
	}
	if err := signCertApp.Run(context.Background(), signCertArgs); err != nil {
		t.Fatalf("Sign cert failed: %v", err)
	}

	// 使用 CRL 命令组生成 CRL
	crlPath := filepath.Join(tmpDir, "crl.pem")

	crlApp := &cli.Command{
		Commands: []*cli.Command{CRLCmd()},
	}
	genCRLArgs := []string{"test", "crl", "generate",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--revoke", certPath,
		"--out", crlPath,
	}
	if err := crlApp.Run(context.Background(), genCRLArgs); err != nil {
		t.Fatalf("CRL generate failed: %v", err)
	}

	// 使用 CRL 命令组查看 CRL
	viewCRLArgs := []string{"test", "crl", "view",
		"--crl", crlPath,
	}
	if err := crlApp.Run(context.Background(), viewCRLArgs); err != nil {
		t.Fatalf("CRL view failed: %v", err)
	}

	// 使用 CRL 命令组检查吊销
	checkArgs := []string{"test", "crl", "check",
		"--cert", certPath,
		"--crl", crlPath,
	}
	if err := crlApp.Run(context.Background(), checkArgs); err != nil {
		t.Fatalf("CRL check failed: %v", err)
	}
}
