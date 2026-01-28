//
// FilePath    : cert\internal\cli\decrypt.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 解密命令
//

package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/jiaopengzi/go-utils/cert"
	"github.com/urfave/cli/v3"
)

// DecryptCmd 返回解密命令
func DecryptCmd() *cli.Command {
	return &cli.Command{
		Name:    "decrypt",
		Aliases: []string{"dec"},
		Usage:   "Decrypt a string using certificate private key (使用证书私钥解密字符串)",
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
				Usage:    "Encrypted data (Base64 encoded) (加密数据 (Base64 编码))",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			certPEM, err := os.ReadFile(cmd.String("cert"))
			if err != nil {
				return fmt.Errorf("read certificate failed (读取证书失败: %w)", err)
			}

			keyPEM, err := os.ReadFile(cmd.String("key"))
			if err != nil {
				return fmt.Errorf("read private key failed (读取私钥失败: %w)", err)
			}

			// 解码 Base64 密文
			ciphertext, err := base64.StdEncoding.DecodeString(cmd.String("data"))
			if err != nil {
				return fmt.Errorf("decode ciphertext failed (解码密文失败: %w)", err)
			}

			plaintext, err := cert.DecryptWithKey(string(certPEM), string(keyPEM), ciphertext)
			if err != nil {
				return fmt.Errorf("decrypt failed (解密失败: %w)", err)
			}

			fmt.Printf("Decrypted data (解密结果:\n%s)", string(plaintext))

			return nil
		},
	}
}
