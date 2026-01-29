//
// FilePath    : cert\internal\cli\signcore.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 签发证书命令
//

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// SignCertCmd 返回签发证书命令
func SignCertCmd() *cli.Command {
	return &cli.Command{
		Name:    "signcert",
		Aliases: []string{"sc"},
		Usage:   "Sign a new certificate using CA (使用 CA 签发新证书)",
		Flags: []cli.Flag{
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
				Name:    "cert-out",
				Aliases: []string{"c"},
				Value:   "core.pem",
				Usage:   "Output path for signed certificate (签发证书输出路径)",
			},
			&cli.StringFlag{
				Name:    "key-out",
				Aliases: []string{"k"},
				Value:   "cert_key.pem",
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
			&cli.IntFlag{
				Name:    "days",
				Aliases: []string{"d"},
				Value:   365,
				Usage:   "Certificate validity in days (证书有效期(天))",
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
				Name:  "dns-names",
				Value: "",
				Usage: "DNS names (comma separated) (DNS 名称(逗号分隔))",
			},
			&cli.StringFlag{
				Name:  "ip-addrs",
				Value: "",
				Usage: "IP addresses (comma separated) (IP 地址(逗号分隔))",
			},
			&cli.StringFlag{
				Name:  "usage",
				Value: "server",
				Usage: "Certificate usage: server, client, codesigning, email (证书用途)",
			},
			&cli.BoolFlag{
				Name:  "is-ca",
				Value: false,
				Usage: "Generate intermediate CA certificate (生成中间 CA 证书)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			caCert, err := os.ReadFile(cmd.String("ca-cert"))
			if err != nil {
				return fmt.Errorf("read CA certificate failed (读取 CA 证书失败: %w)", err)
			}

			caKey, err := os.ReadFile(cmd.String("ca-key"))
			if err != nil {
				return fmt.Errorf("read CA private key failed (读取 CA 私钥失败: %w)", err)
			}

			sanConfig := core.ParseSANFromStr(cmd.String("dns-names"), cmd.String("ip-addrs"))

			usage := parseUsage(cmd.String("usage"))

			cfg := &core.CASignedCertConfig{
				CACert:       string(caCert),
				CAKey:        string(caKey),
				Name:         cmd.String("cn"),
				KeyAlgorithm: core.KeyAlgorithm(cmd.String("algorithm")),
				RSAKeyBits:   int(cmd.Int("rsa-bits")),
				ECDSACurve:   core.ECDSACurve(cmd.String("ecdsa-curve")),
				DaysValid:    int(cmd.Int("days")),
				SAN:          sanConfig,
				Usage:        usage,
				IsCA:         cmd.Bool("is-ca"),
				Subject: core.Subject{
					CommonName:   cmd.String("cn"),
					Organization: cmd.String("org"),
					Country:      cmd.String("country"),
				},
			}

			if err := core.GenerateCASignedCert(cfg); err != nil {
				return fmt.Errorf("sign certificate failed (签发证书失败: %w)", err)
			}

			certOut := cmd.String("cert-out")
			keyOut := cmd.String("key-out")

			if err := os.WriteFile(certOut, []byte(cfg.Cert), 0600); err != nil {
				return fmt.Errorf("write certificate failed (写入证书失败: %w)", err)
			}

			if err := os.WriteFile(keyOut, []byte(cfg.Key), 0600); err != nil {
				return fmt.Errorf("write private key failed (写入私钥失败: %w)", err)
			}

			fmt.Printf("Certificate signed successfully (证书签发成功)")
			fmt.Printf("  Certificate (证书: %s)", certOut)
			fmt.Printf("  Private key (私钥: %s)", keyOut)

			return nil
		},
	}
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
