//
// FilePath    : cert\internal\cli\genrootca.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 生成根证书命令
//

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// GenRootCACmd 返回生成根证书命令
func GenRootCACmd() *cli.Command {
	return &cli.Command{
		Name:    "genrootca",
		Aliases: []string{"grc"},
		Usage:   "Generate root CA certificate and key (生成根证书和私钥)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "cert-out",
				Aliases: []string{"c"},
				Value:   "root.pem",
				Usage:   "Output path for certificate (证书输出路径)",
			},
			&cli.StringFlag{
				Name:    "key-out",
				Aliases: []string{"k"},
				Value:   "root_key.pem",
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
				Value:   3650,
				Usage:   "Certificate validity in days (证书有效期(天))",
			},
			&cli.StringFlag{
				Name:  "cn",
				Value: "Root CA",
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
			&cli.IntFlag{
				Name:  "max-path-len",
				Value: -1,
				Usage: "Maximum path length for CA (-1 for unlimited) (CA 最大路径长度)",
			},
			&cli.BoolFlag{
				Name:  "path-len-zero",
				Value: false,
				Usage: "Set as terminal CA (cannot sign sub-CA) (设置为终端 CA)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			days := cmd.Int("days")
			if days <= 0 {
				return fmt.Errorf("days must be greater than 0 (有效期必须大于 0)")
			}

			cfg := &core.CACertConfig{
				KeyAlgorithm: core.KeyAlgorithm(cmd.String("algorithm")),
				RSAKeyBits:   cmd.Int("rsa-bits"),
				ECDSACurve:   core.ECDSACurve(cmd.String("ecdsa-curve")),
				DaysValid:    cmd.Int("days"),
				MaxPathLen:   cmd.Int("max-path-len"),
				PathLenZero:  cmd.Bool("path-len-zero"),
				Subject: core.Subject{
					CommonName:   cmd.String("cn"),
					Organization: cmd.String("org"),
					Country:      cmd.String("country"),
					State:        cmd.String("state"),
					Locality:     cmd.String("locality"),
				},
			}

			if err := core.GenCACert(cfg); err != nil {
				return fmt.Errorf("generate root CA failed (生成根证书失败: %w)", err)
			}

			certOut := cmd.String("cert-out")
			keyOut := cmd.String("key-out")

			if err := os.WriteFile(certOut, []byte(cfg.Cert), 0600); err != nil {
				return fmt.Errorf("write certificate failed (写入证书失败: %w)", err)
			}

			if err := os.WriteFile(keyOut, []byte(cfg.Key), 0600); err != nil {
				return fmt.Errorf("write private key failed (写入私钥失败: %w)", err)
			}

			fmt.Printf("Root CA certificate generated successfully (根证书生成成功)")
			fmt.Printf("  Certificate (证书: %s)", certOut)
			fmt.Printf("  Private key (私钥: %s)", keyOut)

			return nil
		},
	}
}
