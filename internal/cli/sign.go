//
// FilePath    : cert\internal\cli\sign.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 签名命令
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

// SignCmd 返回签名命令
func SignCmd() *cli.Command {
	return &cli.Command{
		Name:    "sign",
		Aliases: []string{"s"},
		Usage:   "Sign a string using certificate private key (使用证书私钥对字符串加签)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "cert",
				Aliases:  []string{"c"},
				Usage:    "Certificate file path (证书文件路径)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Private key file path (私钥文件路径)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "data",
				Aliases:  []string{"d"},
				Usage:    "Data string to sign (待签名的字符串)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			keyPEM, err := os.ReadFile(cmd.String("key"))
			if err != nil {
				return fmt.Errorf("read private key failed (读取私钥失败: %w)", err)
			}

			data := []byte(cmd.String("data"))

			signature, err := core.SignData(string(keyPEM), data)
			if err != nil {
				return fmt.Errorf("sign data failed (签名失败: %w)", err)
			}

			signatureB64 := base64.StdEncoding.EncodeToString(signature)

			fmt.Printf("Signature (Base64) (签名结果 (Base64):\n%s)", signatureB64)

			return nil
		},
	}
}
