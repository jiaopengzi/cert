# FilePath    : cert\run.ps1
# Author      : jiaopengzi
# Blog        : https://jiaopengzi.com
# Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
# Description : 运行脚本，提供代码格式化、单元测试、go lint、构建和运行功能

# 定义可执行文件名称
$BINARY = "cert"

# 显示菜单
Write-Host ""
Write-Host "请选择需要执行的命令："
Write-Host "  1 - 格式化 Go 代码并编译生成 Linux, Windows 和 macOS 二进制文件"
Write-Host "  2 - 编译 Go 代码并生成 Windows 二进制文件"
Write-Host "  3 - 编译 Go 代码并生成 Linux 二进制文件"
Write-Host "  4 - 编译 Go 代码并生成 macOS 二进制文件"
Write-Host "  5 - 编译运行 Go 代码"
Write-Host "  6 - 清理编译生成的二进制文件和缓存文件"
Write-Host "  7 - go lint"
Write-Host "  8 - 运行编译生成的 Windows 二进制文件"
Write-Host "  9 - 单元测试"
Write-Host " 10 - gopls check"
Write-Host " 11 - 格式化代码"
Write-Host " 12 - 运行 Web 服务器"
Write-Host ""

# 接收用户输入的操作编号
$choice = Read-Host "请输入编号选择对应的操作"
Write-Host ""

# 全部操作：格式化代码, 检查静态错误, 为所有平台生成二进制文件
function all {
    buildEnvInit
    goLint
    buildLinux
    buildWindows
    buildMacos
    restoreWindows
    Write-Host "✅ 全部操作执行完毕"
}

# 初始化 Go 环境变量 设置国内代理和禁用 CGO
function buildEnvInit {
    go env -w GO111MODULE=on
    go env -w CGO_ENABLED=0
    go env -w GOARCH=amd64
    go env -w GOPROXY="https://proxy.golang.com.cn,https://goproxy.cn,https://proxy.golang.org,direct"
    go mod tidy
}

# 为 Windows 系统编译 Go 代码并生成可执行文件 并复制 static 目录到 bin/windows 目录下
function buildWindows {
    go env -w GOOS=windows
    go build -trimpath -ldflags "-s -w" -o "./bin/windows/$BINARY-windows.exe" ./cmd/cert
    Copy-Item -Recurse -Force .\static .\bin\windows\static
    Write-Host "✅ Windows 二进制文件生成完毕"
}

# 为 Windows 系统编译 Go 代码并生成可执行文件, 并将环境变量恢复到默认设置
function buildWindowsRestoreWindowsEnv {
    buildEnvInit
    buildWindows
    restoreWindows
}

# 为 Linux 系统编译 Go 代码并生成可执行文件 并复制 static 目录到 bin/linux 目录下
function buildLinux {
    go env -w GOOS=linux
    go build -trimpath -ldflags "-s -w" -o "./bin/linux/$BINARY-linux" ./cmd/cert
    Copy-Item -Recurse -Force .\static .\bin\linux\static
    Write-Host "✅ Linux 二进制文件生成完毕"
}

# 为 linux 系统编译 Go 代码并生成可执行文件, 并将环境变量恢复到默认设置
function buildLinuxRestoreWindowsEnv {
    buildEnvInit
    buildLinux
    restoreWindows
}

# 为 macOS 系统编译 Go 代码并生成可执行文件 并复制 static 目录到 bin/macos 目录下
function buildMacos {
    go env -w GOOS=darwin
    go build -trimpath -ldflags "-s -w" -o "./bin/macos/$BINARY-macos" ./cmd/cert
    Copy-Item -Recurse -Force .\static .\bin\macos\static
    Write-Host "✅ macOS 二进制文件生成完毕"
}

# 为 macos 系统编译 Go 代码并生成可执行文件, 并将环境变量恢复到默认设置
function buildMacosRestoreWindowsEnv {
    buildEnvInit
    buildMacos
    restoreWindows
}

# 运行编译生成的 Windows 二进制文件
function runOnly {
    & ".\bin\windows\$BINARY-windows.exe" --help
}

# 编译运行 Go 代码
function buildRun {
    go build -trimpath -ldflags "-s -w" -o "./bin/windows/$BINARY-windows.exe" ./cmd/cert
    Copy-Item -Recurse -Force .\static .\bin\windows\static
    runOnly
}

# 使用 golangci-lint run 命令检查代码格式和静态错误
function goLint {
    go vet ./...
    golangci-lint run
    Write-Host "✅ 代码格式和静态检查完毕"
}

# 清理编译生成的二进制文件和缓存文件
function clean {
    go clean
    if (Test-Path .\bin) {
        Remove-Item -Recurse -Force .\bin
    }
    Write-Host "✅ 编译生成的二进制文件和缓存文件已清理"
}

# 将环境变量恢复到默认设置(Windows 系统)
function restoreWindows {
    go env -w CGO_ENABLED=1
    go env -w GOOS=windows
    Write-Host "✅ 环境变量已恢复到 windows 默认设置"
}

# 单元测试
function test {
    go test -v ./...
}

# gopls check 检查代码格式和静态错误
function goplsCheck {
    # 运行前添加策略 Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    # 这个脚本使用 gopls check 检查当前目录及其子目录中的所有 Go 文件。
    # 主要是在 gopls 升级后或者go版本升级后检查代码是否有问题.

    # 拿到当前目录下所有的 .go 文件数量
    $goFilesCount = Get-ChildItem -Path . -Filter *.go -File -Recurse | Measure-Object | Select-Object -ExpandProperty Count

    # 每分钟大约处理文件为 26 个, 计算出大概所需时间(秒)
    $estimatedTime = [Math]::Round($goFilesCount / 26 * 60)

    # 获取当前目录及其子目录中的所有 .go 文件
    $goFiles = Get-ChildItem -Recurse -Filter *.go

    # 记录开始时间
    $startTime = Get-Date

    # 设置定时器间隔
    $interval = 60

    # 初始化已检查文件数量
    $checkedFileCount = 0

    # 初始化上次输出时间
    $lastOutputTime = $startTime

    # 遍历每个 .go 文件并运行 gopls check 命令
    Write-Host "正在检查, 耗时预估 $estimatedTime 秒, 请耐心等待..." -ForegroundColor Green
    foreach ($file in $goFiles) {
        # Write-Host "正在检查 $($file.FullName)..."
        gopls check $file.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Host "检查 $($file.FullName) 时出错" -ForegroundColor Red
        } 
        $checkedFileCount++

        # 获取当前时间
        $currentTime = Get-Date
        $elapsedTime = $currentTime - $startTime

        # 检查是否已经超过了设定的时间间隔
        if (($currentTime - $lastOutputTime).TotalSeconds -ge $interval) {
            $roundedElapsedTime = [Math]::Round($elapsedTime.TotalSeconds)
            Write-Host "当前已耗时 $roundedElapsedTime 秒, 已检查文件数量: $checkedFileCount" -ForegroundColor Yellow
            # 更新上次输出时间
            $lastOutputTime = $currentTime
        }
    }

    # 记录结束时间
    $endTime = Get-Date

    # 计算耗时时间
    $elapsedTime = $endTime - $startTime

    # 显示总耗时时间和总文件数量
    $roundedElapsedTime = [Math]::Round($elapsedTime.TotalSeconds)
    Write-Host "检查结束, 总耗时 $roundedElapsedTime 秒, 总文件数量: $($goFiles.Count), 已检查文件数量: $checkedFileCount" -ForegroundColor Green
}

# 格式化代码
function formatCode {
    go fmt ./...
}

# 运行 Web 服务器
function runWeb {
    Write-Host "正在启动 Web 服务器 (端口 8866)..." -ForegroundColor Green
    go run ./cmd/cert web -p 8866 -s static
}

# switch 要放到最后 
# 执行用户选择的操作
switch ($choice) {
    1 { all }
    2 { buildWindowsRestoreWindowsEnv }
    3 { buildLinuxRestoreWindowsEnv }
    4 { buildMacosRestoreWindowsEnv }
    5 { buildRun }
    6 { clean }
    7 { goLint }
    8 { runOnly }
    9 { test }
    10 { goplsCheck }
    11 { formatCode }
    12 { runWeb }
    default { Write-Host "❌ 无效的选择" }
}