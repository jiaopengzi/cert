//
// FilePath    : cert\internal\cli\validatechain.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书链验证命令
//

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// ValidateChainCmd 返回证书链验证命令
func ValidateChainCmd() *cli.Command {
	return &cli.Command{
		Name:    "validatechain",
		Aliases: []string{"vc"},
		Usage:   "Validate certificate chain (验证证书链)",
		Flags:   validateChainFlags(),
		Action:  validateChainAction,
	}
}

// validateChainFlags 返回验证证书链命令的标志
func validateChainFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "ca-cert",
			Aliases:  []string{"ca"},
			Usage:    "CA certificate file path (CA 证书文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "cert",
			Aliases:  []string{"c"},
			Usage:    "Certificate to validate (待验证的证书文件路径)",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:    "intermediate",
			Aliases: []string{"i"},
			Usage:   "Intermediate CA certificates (中间 CA 证书文件路径(可多次指定))",
		},
		&cli.StringFlag{
			Name:  "dns-name",
			Usage: "DNS name to verify (要验证的 DNS 名称)",
		},
		&cli.StringFlag{
			Name:  "usage",
			Value: "",
			Usage: "Certificate usage to verify: server, client, codesigning, email (要验证的证书用途)",
		},
	}
}

// validateChainAction 执行证书链验证
func validateChainAction(ctx context.Context, cmd *cli.Command) error {
	caCert, err := os.ReadFile(cmd.String("ca-cert"))
	if err != nil {
		return fmt.Errorf("read CA certificate failed (读取 CA 证书失败: %w)", err)
	}

	certPEM, err := os.ReadFile(cmd.String("cert"))
	if err != nil {
		return fmt.Errorf("read certificate failed (读取证书失败: %w)", err)
	}

	intermediateCAs, err := readIntermediateCAs(cmd.StringSlice("intermediate"))
	if err != nil {
		return err
	}

	usage := getValidateUsage(cmd.String("usage"))

	cfg := &core.CertValidateConfig{
		Cert:            string(certPEM),
		CACert:          string(caCert),
		IntermediateCAs: intermediateCAs,
		DNSName:         cmd.String("dns-name"),
		Usage:           usage,
	}

	if err := core.ValidateCert(cfg); err != nil {
		fmt.Printf("Certificate validation FAILED (证书验证失败: %v)", err)
		return nil
	}

	fmt.Printf("Certificate validation PASSED (证书验证通过)")

	return nil
}

// readIntermediateCAs 读取中间证书文件
func readIntermediateCAs(paths []string) ([]string, error) {
	var intermediateCAs []string

	for _, path := range paths {
		interCert, err := os.ReadFile(path) //nolint:gosec // G304: file path is user-provided CLI input
		if err != nil {
			return nil, fmt.Errorf("read intermediate certificate failed (读取中间证书失败: %w)", err)
		}

		intermediateCAs = append(intermediateCAs, string(interCert))
	}

	return intermediateCAs, nil
}

// getValidateUsage 获取验证用途
func getValidateUsage(usageStr string) core.CertUsage {
	if usageStr == "" {
		return 0
	}

	return parseUsage(usageStr)
}
