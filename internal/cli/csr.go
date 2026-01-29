//
// FilePath    : cert\internal\cli\csr.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CSR 相关命令
//

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// genCSRFlags 返回生成 CSR 通用 flags
func genCSRFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "csr-out",
			Aliases: []string{"o"},
			Value:   "request.csr",
			Usage:   "Output path for CSR (CSR 输出路径)",
		},
		&cli.StringFlag{
			Name:    "key-out",
			Aliases: []string{"k"},
			Value:   "request_key.pem",
			Usage:   "Output path for private key (私钥输出路径)",
		},
		&cli.StringFlag{
			Name:    "algorithm",
			Aliases: []string{"a"},
			Value:   "RSA",
			Usage:   "Key algorithm: RSA, ECDSA, Ed25519 (密钥算法)",
		},
		&cli.IntFlag{
			Name:    "rsa-bits",
			Aliases: []string{"b"},
			Value:   2048,
			Usage:   "RSA key bits (2048 or 4096) (RSA 密钥位数)",
		},
		&cli.StringFlag{
			Name:    "ecdsa-curve",
			Aliases: []string{"e"},
			Value:   "P256",
			Usage:   "ECDSA curve: P256, P384, P521 (ECDSA 曲线)",
		},
		&cli.StringFlag{
			Name:  "cn",
			Value: "localhost",
			Usage: "Common Name (通用名称)",
		},
		&cli.StringFlag{
			Name:  "org",
			Value: "",
			Usage: "Organization (组织)",
		},
		&cli.StringFlag{
			Name:  "country",
			Value: "",
			Usage: "Country (国家)",
		},
		&cli.StringFlag{
			Name:  "state",
			Value: "",
			Usage: "State/Province (省份)",
		},
		&cli.StringFlag{
			Name:  "locality",
			Value: "",
			Usage: "Locality/City (城市)",
		},
		&cli.StringFlag{
			Name:  "dns-names",
			Value: "",
			Usage: "DNS names (comma separated) (DNS 名称(逗号分隔))",
		},
		&cli.StringFlag{
			Name:  "ip-addrs",
			Value: "",
			Usage: "IP addresses (comma separated) (IP 地址(逗号分隔))",
		},
	}
}

// genCSRAction 生成 CSR 的公共 action 函数
func genCSRAction(_ context.Context, cmd *cli.Command) error {
	sanConfig := core.ParseSANFromStr(cmd.String("dns-names"), cmd.String("ip-addrs"))

	cfg := &core.CSRConfig{
		KeyAlgorithm: core.KeyAlgorithm(cmd.String("algorithm")),
		RSAKeyBits:   int(cmd.Int("rsa-bits")),
		ECDSACurve:   core.ECDSACurve(cmd.String("ecdsa-curve")),
		SAN:          sanConfig,
		Subject: core.Subject{
			CommonName:   cmd.String("cn"),
			Organization: cmd.String("org"),
			Country:      cmd.String("country"),
			State:        cmd.String("state"),
			Locality:     cmd.String("locality"),
		},
	}

	if err := core.GenerateCSR(cfg); err != nil {
		return fmt.Errorf("generate CSR failed (生成 CSR 失败): %w", err)
	}

	csrOut := cmd.String("csr-out")
	keyOut := cmd.String("key-out")

	if err := os.WriteFile(csrOut, []byte(cfg.CSR), 0600); err != nil {
		return fmt.Errorf("write CSR failed (写入 CSR 失败): %w", err)
	}

	if err := os.WriteFile(keyOut, []byte(cfg.Key), 0600); err != nil {
		return fmt.Errorf("write private key failed (写入私钥失败): %w", err)
	}

	fmt.Println("CSR generated successfully (CSR 生成成功)")
	fmt.Printf("  CSR (CSR 文件): %s\n", csrOut)
	fmt.Printf("  Private key (私钥): %s\n", keyOut)

	return nil
}

// signCSRFlags 返回签发 CSR 通用 flags
func signCSRFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "ca-cert",
			Aliases:  []string{"ca"},
			Usage:    "CA certificate file path (CA 证书文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "ca-key",
			Aliases:  []string{"cakey"},
			Usage:    "CA private key file path (CA 私钥文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "csr",
			Aliases:  []string{"c"},
			Usage:    "CSR file path (CSR 文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:    "cert-out",
			Aliases: []string{"o"},
			Value:   "signed.pem",
			Usage:   "Output path for signed certificate (签发证书输出路径)",
		},
		&cli.IntFlag{
			Name:    "days",
			Aliases: []string{"d"},
			Value:   365,
			Usage:   "Certificate validity in days (证书有效期(天))",
		},
		&cli.StringFlag{
			Name:  "usage",
			Value: "server",
			Usage: "Certificate usage: server, client, codesigning, email (证书用途)",
		},
		&cli.BoolFlag{
			Name:  "is-ca",
			Value: false,
			Usage: "Sign as CA certificate (作为 CA 证书签发)",
		},
	}
}

// signCSRAction 签发 CSR 的公共 action 函数
func signCSRAction(_ context.Context, cmd *cli.Command) error {
	caCert, err := os.ReadFile(cmd.String("ca-cert"))
	if err != nil {
		return fmt.Errorf("read CA certificate failed (读取 CA 证书失败): %w", err)
	}

	caKey, err := os.ReadFile(cmd.String("ca-key"))
	if err != nil {
		return fmt.Errorf("read CA private key failed (读取 CA 私钥失败): %w", err)
	}

	csrPEM, err := os.ReadFile(cmd.String("csr"))
	if err != nil {
		return fmt.Errorf("read CSR failed (读取 CSR 失败): %w", err)
	}

	usage := parseUsage(cmd.String("usage"))

	cfg := &core.CSRSignConfig{
		CACert:    string(caCert),
		CAKey:     string(caKey),
		CSR:       string(csrPEM),
		DaysValid: int(cmd.Int("days")),
		Usage:     usage,
		IsCA:      cmd.Bool("is-ca"),
	}

	if err := core.SignCSR(cfg); err != nil {
		return fmt.Errorf("sign CSR failed (签发 CSR 失败): %w", err)
	}

	certOut := cmd.String("cert-out")

	if err := os.WriteFile(certOut, []byte(cfg.Cert), 0600); err != nil {
		return fmt.Errorf("write certificate failed (写入证书失败): %w", err)
	}

	fmt.Println("CSR signed successfully (CSR 签发成功)")
	fmt.Printf("  Certificate (证书): %s\n", certOut)

	return nil
}

// GenCSRCmd 返回生成 CSR 命令
func GenCSRCmd() *cli.Command {
	return &cli.Command{
		Name:    "gencsr",
		Aliases: []string{"gcsr"},
		Usage:   "Generate Certificate Signing Request (生成证书签名请求)",
		Flags:   genCSRFlags(),
		Action:  genCSRAction,
	}
}

// SignCSRCmd 返回签发 CSR 命令
func SignCSRCmd() *cli.Command {
	return &cli.Command{
		Name:    "signcsr",
		Aliases: []string{"scsr"},
		Usage:   "Sign CSR with CA certificate (使用 CA 签发 CSR)",
		Flags:   signCSRFlags(),
		Action:  signCSRAction,
	}
}

// CSRCmd 返回 CSR 命令组
func CSRCmd() *cli.Command {
	return &cli.Command{
		Name:    "csr",
		Aliases: []string{},
		Usage:   "CSR related commands (CSR 相关命令)",
		Commands: []*cli.Command{
			{
				Name:    "generate",
				Aliases: []string{"gen"},
				Usage:   "Generate Certificate Signing Request (生成证书签名请求)",
				Flags:   genCSRFlags(),
				Action:  genCSRAction,
			},
			{
				Name:    "sign",
				Aliases: []string{"s"},
				Usage:   "Sign CSR with CA certificate (使用 CA 签发 CSR)",
				Flags:   signCSRFlags(),
				Action:  signCSRAction,
			},
		},
	}
}
