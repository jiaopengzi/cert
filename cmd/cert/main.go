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
	"runtime/debug"

	ucli "github.com/urfave/cli/v3"

	"github.com/jiaopengzi/cert/internal/cli"
	"github.com/jiaopengzi/cert/internal/web"
)

// Version 软件版本号，构建时通过 ldflags 注入
var Version = "dev"

// Commit 提交 Git Commit Hash，构建时通过 ldflags 注入
var Commit = "unknown"

// BuildTime 构建时间，构建时通过 ldflags 注入
var BuildTime = "unknown"

func main() {
	// 尝试使用 build info 填充版本信息（仅当 ldflags 未注入时生效）
	if bi, ok := debug.ReadBuildInfo(); ok {
		applyBuildInfo(bi)
	}

	// 组合完整版本信息
	fullVersion := fmt.Sprintf("%s\nCommit: %s\nBuildTime: %s", Version, Commit, BuildTime)

	app := &ucli.Command{
		Name:    "cert",
		Usage:   "A simple certificate tool (简单的证书工具)",
		Version: Version,
		Commands: []*ucli.Command{
			cli.VersionCmd(fullVersion),
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
			port := cmd.Int("port")
			host := cmd.String("host")
			staticDir := cmd.String("static")

			return web.StartServer(host, port, staticDir, Version)
		},
	}
}

// applyBuildInfo 根据 debug.BuildInfo 填充版本信息。
// 优先保留通过 ldflags 已设置的值（非默认值），只有在默认值时才使用 build info。
func applyBuildInfo(bi *debug.BuildInfo) {
	if bi == nil {
		return
	}

	applyVersion(bi.Main.Version)
	applyVCSSettings(bi.Settings)
}

// applyVersion 如果 Version 仍为默认值，则使用 build info 中的版本。
func applyVersion(v string) {
	if !isDefaultVersion(Version) {
		return
	}

	if v != "" && v != "(devel)" {
		Version = v
	}
}

// isDefaultVersion 判断版本是否为默认值。
func isDefaultVersion(v string) bool {
	return v == "dev" || v == ""
}

// isDefaultValue 判断值是否为默认值。
func isDefaultValue(v string) bool {
	return v == "unknown" || v == ""
}

// applyVCSSettings 从 build settings 中提取 vcs.revision 和 vcs.time。
func applyVCSSettings(settings []debug.BuildSetting) {
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			applyCommit(s.Value)
		case "vcs.time":
			applyBuildTime(s.Value)
		}
	}
}

// applyCommit 如果 Commit 为默认值，则使用给定值。
func applyCommit(v string) {
	if isDefaultValue(Commit) && v != "" {
		Commit = v
	}
}

// applyBuildTime 如果 BuildTime 为默认值，则使用给定值。
func applyBuildTime(v string) {
	if isDefaultValue(BuildTime) && v != "" {
		BuildTime = v
	}
}
