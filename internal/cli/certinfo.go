//
// FilePath    : cert\internal\cli\certinfo.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 查看证书信息命令
//

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// CertInfoCmd 返回查看证书信息命令
func CertInfoCmd() *cli.Command {
	return &cli.Command{
		Name:    "certinfo",
		Aliases: []string{"ci"},
		Usage:   "View certificate information (查看证书信息)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "cert",
				Aliases:  []string{"c"},
				Usage:    "Certificate file path (证书文件路径)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			certPEM, err := os.ReadFile(cmd.String("cert"))
			if err != nil {
				return fmt.Errorf("read certificate failed (读取证书失败): %w", err)
			}

			info, err := core.GetCertInfo(string(certPEM))
			if err != nil {
				return fmt.Errorf("parse certificate failed (解析证书失败): %w", err)
			}

			fmt.Println("Certificate Information (证书信息):")
			fmt.Println("=====================================")
			fmt.Printf("Serial Number (序列号): %s\n", info.SerialNumber)
			fmt.Printf("Subject (主题): %s\n", info.Subject)
			fmt.Printf("Issuer (颁发者): %s\n", info.Issuer)
			fmt.Printf("Not Before (生效时间): %s\n", info.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Printf("Not After (过期时间): %s\n", info.NotAfter.Format("2006-01-02 15:04:05"))
			fmt.Printf("Is CA (是否为 CA): %v\n", info.IsCA)
			fmt.Printf("Key Algorithm (密钥算法): %s\n", info.KeyAlgorithm)

			if len(info.DNSNames) > 0 {
				fmt.Printf("DNS Names (DNS 名称): %s\n", strings.Join(info.DNSNames, ", "))
			}

			if len(info.IPAddresses) > 0 {
				fmt.Printf("IP Addresses (IP 地址): %s\n", strings.Join(info.IPAddresses, ", "))
			}

			if len(info.ExtKeyUsages) > 0 {
				fmt.Printf("Extended Key Usage (扩展密钥用途): %s\n", strings.Join(info.ExtKeyUsages, ", "))
			}

			return nil
		},
	}
}
