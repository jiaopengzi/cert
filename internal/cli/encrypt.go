//
// FilePath    : cert\internal\cli\encrypt.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 加密命令
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

// EncryptCmd 返回加密命令
func EncryptCmd() *cli.Command {
	return &cli.Command{
		Name:    "encrypt",
		Aliases: []string{"enc"},
		Usage:   "Encrypt a string using certificate public key (使用证书公钥加密字符串)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "cert",
				Aliases:  []string{"c"},
				Usage:    "Certificate file path (证书文件路径)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "data",
				Aliases:  []string{"d"},
				Usage:    "Plaintext string to encrypt (待加密的明文字符串)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			certPEM, err := os.ReadFile(cmd.String("cert"))
			if err != nil {
				return fmt.Errorf("read certificate failed (读取证书失败: %w)", err)
			}

			plaintext := []byte(cmd.String("data"))

			ciphertext, _, err := cert.EncryptWithCert(string(certPEM), plaintext)
			if err != nil {
				return fmt.Errorf("encrypt failed (加密失败: %w)", err)
			}

			// 密文已经包含了nonce，直接 base64 编码
			result := base64.StdEncoding.EncodeToString(ciphertext)

			fmt.Printf("Encrypted data (Base64) (加密结果 (Base64):\n%s)", result)

			return nil
		},
	}
}
