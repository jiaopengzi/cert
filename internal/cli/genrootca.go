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

	"github.com/urfave/cli/v3"

	"github.com/jiaopengzi/cert/core"
)

// GenRootCACmd 返回生成根证书命令
func GenRootCACmd() *cli.Command {
	return &cli.Command{
		Name:    "genrootca",
		Aliases: []string{"grc"},
		Usage:   "Generate root CA certificate and key (生成根证书和私钥)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    flagNameCertOut,
				Aliases: []string{"c"},
				Value:   "root.pem",
				Usage:   "Output path for certificate (证书输出路径)",
			},
			&cli.StringFlag{
				Name:    flagNameKeyOut,
				Aliases: []string{"k"},
				Value:   "root_key.pem",
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
				Value:   3650,
				Usage:   flagUsageCertDays,
			},
			&cli.StringFlag{
				Name:  "cn",
				Value: "Root CA",
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
			days := cmd.Int(flagNameDays)
			if days <= 0 {
				return fmt.Errorf("days must be greater than 0 (有效期必须大于 0)")
			}

			cfg := &core.CACertConfig{
				KeyAlgorithm: core.KeyAlgorithm(cmd.String(flagNameAlgorithm)),
				RSAKeyBits:   cmd.Int(flagNameRSAKeyBits),
				ECDSACurve:   core.ECDSACurve(cmd.String(flagNameECDSACurve)),
				DaysValid:    cmd.Int(flagNameDays),
				MaxPathLen:   cmd.Int("max-path-len"),
				PathLenZero:  cmd.Bool("path-len-zero"),
				Subject: core.Subject{
					CommonName:   cmd.String("cn"),
					Organization: cmd.String(flagNameOrg),
					Country:      cmd.String(flagNameCountry),
					State:        cmd.String("state"),
					Locality:     cmd.String("locality"),
				},
			}

			if err := core.GenCACert(cfg); err != nil {
				return fmt.Errorf("generate root CA failed (生成根证书失败: %w)", err)
			}

			certOut := cmd.String(flagNameCertOut)
			keyOut := cmd.String(flagNameKeyOut)

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
