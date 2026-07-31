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

	"github.com/urfave/cli/v3"

	"github.com/jiaopengzi/cert/core"
)

// SignCertCmd 返回签发证书命令
func SignCertCmd() *cli.Command {
	return &cli.Command{
		Name:    "signcert",
		Aliases: []string{"sc"},
		Usage:   "Sign a new certificate using CA (使用 CA 签发新证书)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     flagNameCACert,
				Aliases:  []string{"ca"},
				Usage:    flagUsageCACertPath,
				Required: true,
			},
			&cli.StringFlag{
				Name:     flagNameCAKey,
				Aliases:  []string{flagAliasCAKey},
				Usage:    flagUsageCAKeyPath,
				Required: true,
			},
			&cli.StringFlag{
				Name:    flagNameCertOut,
				Aliases: []string{"c"},
				Value:   "core.pem",
				Usage:   "Output path for signed certificate (签发证书输出路径)",
			},
			&cli.StringFlag{
				Name:    flagNameKeyOut,
				Aliases: []string{"k"},
				Value:   "cert_key.pem",
				Usage:   flagUsagePrivateKeyOut,
			},
			&cli.StringFlag{
				Name:    flagNameAlgorithm,
				Aliases: []string{"a"},
				Value:   defaultAlgorithmRSA,
				Usage:   flagUsageKeyAlgorithm,
			},
			&cli.IntFlag{
				Name:    flagNameRSAKeyBits,
				Aliases: []string{"b"},
				Value:   2048,
				Usage:   flagUsageRSAKeyBits,
			},
			&cli.StringFlag{
				Name:    flagNameECDSACurve,
				Aliases: []string{"e"},
				Value:   defaultECDSACurveP256,
				Usage:   flagUsageECDSACurve,
			},
			&cli.IntFlag{
				Name:    flagNameDays,
				Aliases: []string{"d"},
				Value:   365,
				Usage:   flagUsageCertDays,
			},
			&cli.StringFlag{
				Name:  "cn",
				Value: "localhost",
				Usage: flagUsageCommonName,
			},
			&cli.StringFlag{
				Name:  flagNameOrg,
				Value: "",
				Usage: flagUsageOrganization,
			},
			&cli.StringFlag{
				Name:  flagNameCountry,
				Value: "",
				Usage: flagUsageCountry,
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
				Name:  flagNameUsage,
				Value: defaultUsageServer,
				Usage: "Certificate usage: server, client, codesigning, email (证书用途)",
			},
			&cli.BoolFlag{
				Name:  "is-ca",
				Value: false,
				Usage: "Generate intermediate CA certificate (生成中间 CA 证书)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			days := cmd.Int(flagNameDays)
			if days <= 0 {
				return fmt.Errorf("days must be greater than 0 (有效期必须大于 0)")
			}

			caCert, err := os.ReadFile(cmd.String(flagNameCACert))
			if err != nil {
				return fmt.Errorf("read CA certificate failed (读取 CA 证书失败: %w)", err)
			}

			caKey, err := os.ReadFile(cmd.String(flagNameCAKey))
			if err != nil {
				return fmt.Errorf("read CA private key failed (读取 CA 私钥失败: %w)", err)
			}

			sanConfig := core.ParseSANFromStr(cmd.String("dns-names"), cmd.String("ip-addrs"))

			usage := parseUsage(cmd.String(flagNameUsage))

			cfg := &core.CASignedCertConfig{
				CACert:       string(caCert),
				CAKey:        string(caKey),
				Name:         cmd.String("cn"),
				KeyAlgorithm: core.KeyAlgorithm(cmd.String(flagNameAlgorithm)),
				RSAKeyBits:   cmd.Int(flagNameRSAKeyBits),
				ECDSACurve:   core.ECDSACurve(cmd.String(flagNameECDSACurve)),
				DaysValid:    cmd.Int(flagNameDays),
				SAN:          sanConfig,
				Usage:        usage,
				IsCA:         cmd.Bool("is-ca"),
				Subject: core.Subject{
					CommonName:   cmd.String("cn"),
					Organization: cmd.String(flagNameOrg),
					Country:      cmd.String(flagNameCountry),
				},
			}

			if err := core.GenerateCASignedCert(cfg); err != nil {
				return fmt.Errorf("sign certificate failed (签发证书失败: %w)", err)
			}

			certOut := cmd.String(flagNameCertOut)
			keyOut := cmd.String(flagNameKeyOut)

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
	case defaultUsageServer:
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
