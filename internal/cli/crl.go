//
// FilePath    : cert\internal\cli\crl.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : CRL 相关命令
//

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/core"
	"github.com/urfave/cli/v3"
)

// genCRLFlags 返回生成 CRL 通用 flags
func genCRLFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "ca-cert",
			Aliases:  []string{"ca"},
			Usage:    "CA certificate file path (CA 证书文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "ca-key",
			Aliases:  []string{"cakey"},
			Usage:    "CA private key file path (CA 私钥文件路径)",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:    "revoke",
			Aliases: []string{"r"},
			Usage:   "Certificate files to revoke (要吊销的证书文件路径，可多次指定)",
		},
		&cli.IntFlag{
			Name:    "days",
			Aliases: []string{"d"},
			Value:   30,
			Usage:   "CRL validity in days (CRL 有效期(天))",
		},
		&cli.StringFlag{
			Name:    "out",
			Aliases: []string{"o"},
			Value:   "crl.pem",
			Usage:   "Output path for CRL (CRL 输出路径)",
		},
	}
}

// genCRLAction 生成 CRL 的公共 action 函数
func genCRLAction(_ context.Context, cmd *cli.Command) error {
	caCert, err := os.ReadFile(cmd.String("ca-cert"))
	if err != nil {
		return fmt.Errorf("read CA certificate failed (读取 CA 证书失败): %w", err)
	}

	caKey, err := os.ReadFile(cmd.String("ca-key"))
	if err != nil {
		return fmt.Errorf("read CA private key failed (读取 CA 私钥失败): %w", err)
	}

	// 读取要吊销的证书
	var revokedCerts []string

	for _, certPath := range cmd.StringSlice("revoke") {
		certData, readErr := os.ReadFile(certPath)
		if readErr != nil {
			return fmt.Errorf("read revoked certificate %s failed (读取吊销证书失败): %w", certPath, readErr)
		}

		revokedCerts = append(revokedCerts, string(certData))
	}

	cfg := &core.CRLConfig{
		CACert:       string(caCert),
		CAKey:        string(caKey),
		RevokedCerts: revokedCerts,
		DaysValid:    int(cmd.Int("days")),
	}

	if err := core.GenerateCRL(cfg); err != nil {
		return fmt.Errorf("generate CRL failed (生成 CRL 失败): %w", err)
	}

	outPath := cmd.String("out")
	if err := os.WriteFile(outPath, []byte(cfg.CRL), 0600); err != nil {
		return fmt.Errorf("write CRL failed (写入 CRL 失败): %w", err)
	}

	fmt.Println("CRL generated successfully (CRL 生成成功)")
	fmt.Printf("  Output (输出文件): %s\n", outPath)
	fmt.Printf("  This Update (本次更新): %s\n", cfg.ThisUpdate.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Next Update (下次更新): %s\n", cfg.NextUpdate.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Revoked Count (吊销数量): %d\n", len(cfg.RevokedSerials))

	return nil
}

// viewCRLFlags 返回查看 CRL 通用 flags
func viewCRLFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "crl",
			Aliases:  []string{"c"},
			Usage:    "CRL file path (CRL 文件路径)",
			Required: true,
		},
	}
}

// viewCRLAction 查看 CRL 的公共 action 函数
func viewCRLAction(_ context.Context, cmd *cli.Command) error {
	crlPEM, err := os.ReadFile(cmd.String("crl"))
	if err != nil {
		return fmt.Errorf("read CRL failed (读取 CRL 失败): %w", err)
	}

	revokedCerts, err := core.ParseCRL(string(crlPEM))
	if err != nil {
		return fmt.Errorf("parse CRL failed (解析 CRL 失败): %w", err)
	}

	fmt.Println("CRL Information (CRL 信息):")
	fmt.Println("=====================================")
	fmt.Printf("Revoked Certificates Count (吊销证书数量): %d\n", len(revokedCerts))

	if len(revokedCerts) > 0 {
		fmt.Println("\nRevoked Certificates (已吊销证书):")

		for i, cert := range revokedCerts {
			fmt.Printf("  %d. Serial: %s, Revoked At: %s\n",
				i+1,
				cert.SerialNumber.String(),
				cert.RevocationTime.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

// checkRevokedFlags 返回检查证书吊销状态通用 flags
func checkRevokedFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "cert",
			Aliases:  []string{"c"},
			Usage:    "Certificate file path (证书文件路径)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "crl",
			Usage:    "CRL file path (CRL 文件路径)",
			Required: true,
		},
	}
}

// checkRevokedAction 检查证书吊销状态的公共 action 函数
func checkRevokedAction(_ context.Context, cmd *cli.Command) error {
	certPEM, err := os.ReadFile(cmd.String("cert"))
	if err != nil {
		return fmt.Errorf("read certificate failed (读取证书失败): %w", err)
	}

	crlPEM, err := os.ReadFile(cmd.String("crl"))
	if err != nil {
		return fmt.Errorf("read CRL failed (读取 CRL 失败): %w", err)
	}

	revoked, err := core.IsCertRevoked(string(certPEM), string(crlPEM))
	if err != nil {
		return fmt.Errorf("check revocation failed (检查吊销状态失败): %w", err)
	}

	// 获取证书信息用于显示
	var certDesc string
	if info, infoErr := core.GetCertInfo(string(certPEM)); infoErr == nil && info != nil {
		certDesc = fmt.Sprintf("(Serial: %s)", info.SerialNumber)
	}

	if revoked {
		fmt.Printf("Certificate %s is REVOKED (证书已被吊销)\n", certDesc)
	} else {
		fmt.Printf("Certificate %s is NOT revoked (证书未被吊销)\n", certDesc)
	}

	return nil
}

// GenCRLCmd 返回生成 CRL 命令
func GenCRLCmd() *cli.Command {
	return &cli.Command{
		Name:    "gencrl",
		Aliases: []string{"gcrl"},
		Usage:   "Generate Certificate Revocation List (生成证书吊销列表)",
		Flags:   genCRLFlags(),
		Action:  genCRLAction,
	}
}

// ViewCRLCmd 返回查看 CRL 命令
func ViewCRLCmd() *cli.Command {
	return &cli.Command{
		Name:    "viewcrl",
		Aliases: []string{"vcrl"},
		Usage:   "View Certificate Revocation List (查看证书吊销列表)",
		Flags:   viewCRLFlags(),
		Action:  viewCRLAction,
	}
}

// CheckRevokedCmd 返回检查证书吊销状态命令
func CheckRevokedCmd() *cli.Command {
	return &cli.Command{
		Name:    "checkrevoked",
		Aliases: []string{"cr"},
		Usage:   "Check if a certificate is revoked (检查证书是否被吊销)",
		Flags:   checkRevokedFlags(),
		Action:  checkRevokedAction,
	}
}

// CRLCmd 返回 CRL 命令组
func CRLCmd() *cli.Command {
	return &cli.Command{
		Name:    "crl",
		Aliases: []string{},
		Usage:   "CRL related commands (CRL 相关命令)",
		Commands: []*cli.Command{
			{
				Name:    "generate",
				Aliases: []string{"gen"},
				Usage:   "Generate Certificate Revocation List (生成证书吊销列表)",
				Flags:   genCRLFlags(),
				Action:  genCRLAction,
			},
			{
				Name:    "view",
				Aliases: []string{"v"},
				Usage:   "View Certificate Revocation List (查看证书吊销列表)",
				Flags:   viewCRLFlags(),
				Action:  viewCRLAction,
			},
			{
				Name:    "check",
				Aliases: []string{"chk"},
				Usage:   "Check if a certificate is revoked (检查证书是否被吊销)",
				Flags:   checkRevokedFlags(),
				Action:  checkRevokedAction,
			},
		},
	}
}
