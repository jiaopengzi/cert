//
// FilePath    : cert\internal\cli\verify.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 验签命令
//

package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// VerifyCmd 返回验签命令
func VerifyCmd() *cli.Command {
	return &cli.Command{
		Name:    "verify",
		Aliases: []string{"vf"},
		Usage:   "Verify a signature using certificate (使用证书验证签名)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "cert",
				Aliases:  []string{"c"},
				Usage:    "Certificate file path (证书文件路径)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "data",
				Aliases: []string{"d"},
				Usage:   "Original data string (原始数据字符串)",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "Original file path (原始文件路径, 支持二进制文件)",
			},
			&cli.StringFlag{
				Name:     "signature",
				Aliases:  []string{"s"},
				Usage:    "Signature (Base64 encoded) (签名 (Base64 编码))",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			data, err := readInputData(cmd.String("data"), cmd.String("file"))
			if err != nil {
				return err
			}

			certPEM, err := os.ReadFile(cmd.String("cert"))
			if err != nil {
				return fmt.Errorf("read certificate failed (读取证书失败): %w", err)
			}

			signature, err := base64.StdEncoding.DecodeString(cmd.String("signature"))
			if err != nil {
				return fmt.Errorf("decode signature failed (解码签名失败): %w", err)
			}

			if err := core.VerifySignature(string(certPEM), data, signature); err != nil {
				fmt.Printf("Signature verification FAILED (签名验证失败): %v", err)
				return nil
			}

			fmt.Printf("Signature verification PASSED (签名验证通过)")

			return nil
		},
	}
}
