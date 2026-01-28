//
// FilePath    : cert\internal\cli\version.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 版本命令
//

package cli

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// VersionCmd 返回版本命令
func VersionCmd(version string) *cli.Command {
	return &cli.Command{
		Name:    "version",
		Aliases: []string{"v"},
		Usage:   "Show the version (显示版本号)",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			fmt.Printf("cert version %s\n", version)
			return nil
		},
	}
}
