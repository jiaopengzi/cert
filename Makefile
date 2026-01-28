# FilePath    : cert\Makefile
# Author      : jiaopengzi
# Blog        : https://jiaopengzi.com
# Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
# Description : Makefile 用于编译生成不同平台的二进制文件

# 定义伪目标
.PHONY: all build-env-init build-windows build-linux build-macos run lint test clean help

# 可执行文件名称
BINARY=cert

# ----------------------------------------------------------------------
# 编译优化参数
# ----------------------------------------------------------------------

# 默认的编译优化参数
LDFLAGS := -s -w

# 调试显示最终生成的 ldflags
$(info 最终编译参数 ldflags: $(LDFLAGS))

# 默认目标：检查代码格式、静态检查并编译生成所有平台二进制文件
all: lint build-linux build-windows build-macos

# 初始化环境
build-env-init:
	@GO111MODULE=on CGO_ENABLED=0 GOARCH=amd64 go mod tidy

# 编译生成 Windows 平台二进制文件 并复制 static 目录到 bin/windows 目录下
build-windows: build-env-init
	@mkdir -p ./bin/windows/static
	CGO_ENABLED=0 GOOS=windows go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/windows/${BINARY}-windows.exe ./cmd/cert
	cp -r ./static/* ./bin/windows/static/

# 编译生成 Linux 平台二进制文件 并复制 static 目录到 bin/linux 目录下
build-linux: build-env-init
	@mkdir -p ./bin/linux/static
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/linux/${BINARY}-linux ./cmd/cert
	cp -r ./static/* ./bin/linux/static/

# 编译生成 macOS 平台二进制文件 并复制 static 目录到 bin/macos 目录下
build-macos: build-env-init
	@mkdir -p ./bin/macos/static
	CGO_ENABLED=0 GOOS=darwin go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/macos/${BINARY}-macos ./cmd/cert
	cp -r ./static/* ./bin/macos/static/

# 检查代码格式和静态检查
lint:
	golangci-lint run

# 单元测试
test:
	go test -v ./...

# 清理编译生成的二进制文件和缓存文件
clean:
	go clean
	rm -rf ./bin

# 显示帮助信息
help:
	@echo "make - 格式化 Go 代码, 并编译生成 Linux, Windows, macOS 二进制文件"
	@echo "make build-windows - 编译 Go 代码, 生成 Windows 二进制文件"
	@echo "make build-linux - 编译 Go 代码, 生成 Linux 二进制文件"
	@echo "make build-macos - 编译 Go 代码, 生成 macOS 二进制文件"
	@echo "make clean - 清理编译生成的二进制文件和缓存文件"
	@echo "make lint - 检查代码格式和静态检查"
	@echo "make test - 单元测试"
