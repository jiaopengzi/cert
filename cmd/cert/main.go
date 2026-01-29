//
// FilePath    : cert\cmd\cli\main.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书工具 CLI 入口
//

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jiaopengzi/cert/internal/cli"
	"github.com/jiaopengzi/cert/internal/web"
	ucli "github.com/urfave/cli/v3"
)

// Version 软件版本号，构建时通过 ldflags 注入
var Version = "dev"

func main() {
	app := &ucli.Command{
		Name:    "cert",
		Usage:   "A simple certificate tool (简单的证书工具)",
		Version: Version,
		Commands: []*ucli.Command{
			cli.VersionCmd(Version),
			cli.GenRootCACmd(),
			cli.SignCertCmd(),
			cli.CertInfoCmd(),
			cli.SignCmd(),
			cli.VerifyCmd(),
			cli.EncryptCmd(),
			cli.DecryptCmd(),
			cli.ValidateChainCmd(),
			cli.GenCSRCmd(),
			cli.SignCSRCmd(),
			cli.CSRCmd(),
			cli.GenCRLCmd(),
			cli.ViewCRLCmd(),
			cli.CheckRevokedCmd(),
			cli.CRLCmd(),
			webCmd(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// webCmd 返回 Web 服务命令
func webCmd() *ucli.Command {
	return &ucli.Command{
		Name:    "web",
		Aliases: []string{"w"},
		Usage:   "Start web server (启动 Web 服务器)",
		Flags: []ucli.Flag{
			&ucli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   8866,
				Usage:   "Server port (服务器端口)",
			},
			&ucli.StringFlag{
				Name:    "host",
				Aliases: []string{"H"},
				Value:   "localhost",
				Usage:   "Server host (服务器地址)",
			},
			&ucli.StringFlag{
				Name:    "static",
				Aliases: []string{"s"},
				Value:   "static",
				Usage:   "Static files directory (静态文件目录)",
			},
		},
		Action: func(ctx context.Context, cmd *ucli.Command) error {
			port := int(cmd.Int("port"))
			host := cmd.String("host")
			staticDir := cmd.String("static")

			return web.StartServer(host, port, staticDir, Version)
		},
	}
}
