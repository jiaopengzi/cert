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

	"github.com/urfave/cli/v3"

	"github.com/jiaopengzi/cert/core"
)

// readInputData 读取签名/验签的输入数据, 支持字符串和文件两种方式.
func readInputData(dataStr, fileStr string) ([]byte, error) {
	if dataStr == "" && fileStr == "" {
		return nil, fmt.Errorf("must specify --data or --file (必须指定 --data 或 --file)")
	}

	if dataStr != "" && fileStr != "" {
		return nil, fmt.Errorf("cannot specify both --data and --file (不能同时指定 --data 和 --file)")
	}

	if fileStr != "" {
		data, err := os.ReadFile(fileStr) //nolint:gosec // G304: file path is user-provided CLI input
		if err != nil {
			return nil, fmt.Errorf("read file failed (读取文件失败): %w", err)
		}

		return data, nil
	}

	return []byte(dataStr), nil
}

// SignCmd 返回签名命令
func SignCmd() *cli.Command {
	return &cli.Command{
		Name:    "sign",
		Aliases: []string{"s"},
		Usage:   "Sign data using private key (使用私钥对数据加签)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Usage:    "Private key file path (私钥文件路径)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "data",
				Aliases: []string{"d"},
				Usage:   "Data string to sign (待签名的字符串)",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "File path to sign (待签名的文件路径, 支持二进制文件)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			data, err := readInputData(cmd.String("data"), cmd.String("file"))
			if err != nil {
				return err
			}

			keyPEM, err := os.ReadFile(cmd.String("key"))
			if err != nil {
				return fmt.Errorf("read private key failed (读取私钥失败): %w", err)
			}

			signature, err := core.SignData(string(keyPEM), data)
			if err != nil {
				return fmt.Errorf("sign data failed (签名失败): %w", err)
			}

			signatureB64 := base64.StdEncoding.EncodeToString(signature)

			fmt.Printf("Signature (Base64) (签名结果 (Base64)):\n%s", signatureB64)

			return nil
		},
	}
}
