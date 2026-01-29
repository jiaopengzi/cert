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
# 获取 Git 版本信息(用于注入版本、提交哈希、构建时间等 ldflags 参数)
# ----------------------------------------------------------------------

# 参考: https://semver.org/lang/zh-CN/
# 获取最近的符合 1.2.3 0.1.2-beta+251113, 同时兼容带小写v前缀等格式的 Git Tag, 如果没有或不符合格式, 则为 "dev"
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null | grep -E '^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$$' || echo "dev")
# $(info [DEBUG] GIT_TAG = '$(GIT_TAG)')

# 获取当前 Git Commit Hash, 如果获取失败则使用 "unknown"
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
# $(info [DEBUG] GIT_COMMIT = '$(GIT_COMMIT)')

# 获取当前构建时间, 格式：2024-06-15 14:30:00 +08:00
GIT_BUILD_TIME := $(shell dt=$$(date +"%Y-%m-%d %H:%M:%S"); tz=$$(date +"%z" | sed -E 's/^([+-])([0-9]{2})([0-9]{2})$$/\1\2:\3/'); echo "$$dt $$tz")
# $(info [DEBUG] GIT_BUILD_TIME = '$(GIT_BUILD_TIME)')

# ----------------------------------------------------------------------
# 编译优化参数
# ----------------------------------------------------------------------

# 默认的编译优化参数
LDFLAGS := -s -w

# 如果有有效的 Git Tag, 则注入 Version
ifeq ($(GIT_TAG),)
  # 如果没有检测到合法 Tag, 则不注入 Version 参数
else
  LDFLAGS += -X 'main.Version=$(GIT_TAG)'
endif

# 注入 Git Commit Hash(始终注入)
LDFLAGS += -X 'main.Commit=$(GIT_COMMIT)'

# 注入构建时间(始终注入)
LDFLAGS += -X 'main.BuildTime=$(GIT_BUILD_TIME)'

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
