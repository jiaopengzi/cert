# Cert - 简单的证书工具

[![Go Version](https://img.shields.io/badge/Go-1.25.6+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

一个简单易用的证书管理工具，支持 CLI 命令行和 Web 界面两种操作方式。

## 功能特性

- **生成根证书** - 支持 RSA、ECDSA、Ed25519 三种算法
- **签发证书** - 使用 CA 证书签发服务器/客户端/代码签名/邮件证书
- **查看证书信息** - 解析并显示证书的详细信息
- **签名验签** - 使用证书私钥对数据签名和验证
- **加密解密** - 使用证书公钥加密和私钥解密
- **证书链验证** - 验证证书链的有效性
- **CSR 管理** - 生成证书签名请求（CSR）并签发
- **CRL 管理** - 生成、查看证书吊销列表，检查证书吊销状态
- **Web 界面** - 提供友好的 Web 操作界面

## 安装

### 方式一：下载预编译二进制（推荐）

从 [Releases](https://github.com/jiaopengzi/cert/releases) 页面下载对应平台的二进制文件。

> 预编译版本包含完整的版本信息（Version、Commit、BuildTime）。

### 方式二：Go Install

```bash
go install github.com/jiaopengzi/cert/cmd/cert@latest
```

> 此方式安装的版本号来自 Go 模块版本（如 v0.2.0），Commit 和 BuildTime 来自 VCS 信息。

### 方式三：源码编译（完整版本信息）

```bash
git clone https://github.com/jiaopengzi/cert.git
cd cert

# Windows (PowerShell)
.\run.ps1
# 选择 2 - 构建 Windows 二进制

# Linux/macOS
make build-linux   # 或 build-macos
```

> 通过 Makefile/run.ps1 编译会自动注入 Git Tag、Commit Hash 和构建时间。

## 快速开始

### 生成根证书

```bash
# 使用默认参数生成根证书
cert genrootca

# 指定算法和有效期
cert genrootca -a RSA -b 4096 -d 3650 --cn "My Root CA" --org "My Company"

# 使用 ECDSA 算法
cert genrootca -a ECDSA -e P384 --cn "ECDSA Root CA"

# 使用 Ed25519 算法
cert genrootca -a Ed25519 --cn "Ed25519 Root CA"
```

### 签发证书

```bash
# 签发服务器证书
cert signcert --ca-cert root.pem --ca-key root_key.pem \
  --cn localhost --dns-names "localhost,example.com" --ip-addrs "127.0.0.1" \
  --usage server

# 签发客户端证书
cert signcert --ca-cert root.pem --ca-key root_key.pem \
  --cn "Client Cert" --usage client

# 签发中间 CA 证书
cert signcert --ca-cert root.pem --ca-key root_key.pem \
  --cn "Intermediate CA" --is-ca
```

### 签名和验签

```bash
# 对数据签名
cert sign --cert cert.pem --key cert_key.pem --data "Hello, World!"

# 验证签名
cert verify --cert cert.pem --data "Hello, World!" --signature "BASE64_SIGNATURE"
```

### 加密和解密

```bash
# 加密
cert encrypt --cert cert.pem --data "Secret Message"

# 解密
cert decrypt --cert cert.pem --key cert_key.pem --data "BASE64_CIPHERTEXT"
```

### 验证证书链

```bash
# 验证证书链
cert validatechain --ca-cert root.pem --cert server.pem --dns-name localhost --usage server

# 包含中间 CA 验证
cert validatechain --ca-cert root.pem --cert server.pem \
  --intermediate intermediate.pem --dns-name localhost
```

### 查看证书信息

```bash
# 查看证书详细信息
cert certinfo --cert server.pem
```

### CSR 管理

```bash
# 生成 CSR
cert gencsr --cn example.com --dns-names "example.com,www.example.com" --org "My Company"

# 使用 CA 签发 CSR
cert signcsr --ca-cert root.pem --ca-key root_key.pem --csr request.csr --days 365

# 使用命令组
cert csr gen --cn example.com
cert csr sign --ca-cert root.pem --ca-key root_key.pem --csr request.csr
```

### CRL 管理

```bash
# 生成 CRL（吊销证书）
cert gencrl --ca-cert root.pem --ca-key root_key.pem --revoke cert1.pem --revoke cert2.pem

# 追加吊销到现有 CRL
cert gencrl --ca-cert root.pem --ca-key root_key.pem --revoke cert3.pem --existing crl.pem

# 跳过已过期证书，剔除30天前的吊销记录
cert gencrl --ca-cert root.pem --ca-key root_key.pem --revoke cert.pem \
  --existing crl.pem --skip-expired --prune-days 30

# 查看 CRL 内容
cert viewcrl --crl crl.pem

# 检查证书是否被吊销
cert checkrevoked --cert server.pem --crl crl.pem

# 使用命令组
cert crl gen --ca-cert root.pem --ca-key root_key.pem --revoke cert.pem
cert crl view --crl crl.pem
cert crl check --cert server.pem --crl crl.pem
```

### 启动 Web 服务器

```bash
# 使用默认端口 8866 启动
cert web

# 指定端口和静态文件目录
cert web -p 8080 -s ./static
```

访问 `http://localhost:8866` 即可使用 Web 界面。

## CLI 命令参考

| 命令 | 别名 | 说明 |
|------|------|------|
| `version` | `v` | 显示版本号 |
| `genrootca` | `grc` | 生成根证书和私钥 |
| `signcert` | `sc` | 使用 CA 签发新证书 |
| `certinfo` | `ci` | 查看证书信息 |
| `sign` | `s` | 使用证书私钥对字符串加签 |
| `verify` | `vf` | 使用证书验证签名 |
| `encrypt` | `enc` | 使用证书公钥加密字符串 |
| `decrypt` | `dec` | 使用证书私钥解密字符串 |
| `validatechain` | `vc` | 验证证书链 |
| `gencsr` | `gcsr` | 生成证书签名请求 (CSR) |
| `signcsr` | `scsr` | 使用 CA 签发 CSR |
| `csr` | - | CSR 命令组 (gen/sign) |
| `gencrl` | `gcrl` | 生成证书吊销列表 (CRL) |
| `viewcrl` | `vcrl` | 查看 CRL 内容 |
| `checkrevoked` | `cr` | 检查证书是否被吊销 |
| `crl` | - | CRL 命令组 (gen/view/check) |
| `web` | `w` | 启动 Web 服务器 |

使用 `cert <command> --help` 查看各命令的详细参数。

## genrootca 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--cert-out` | `-c` | root.pem | 证书输出路径 |
| `--key-out` | `-k` | root_key.pem | 私钥输出路径 |
| `--algorithm` | `-a` | RSA | 密钥算法：RSA, ECDSA, Ed25519 |
| `--rsa-bits` | `-b` | 2048 | RSA 密钥位数：2048 或 4096 |
| `--ecdsa-curve` | `-e` | P256 | ECDSA 曲线：P256, P384, P521 |
| `--days` | `-d` | 3650 | 证书有效期（天），必须大于 0 |
| `--cn` | - | Root CA | 通用名称 |
| `--org` | - | - | 组织 |
| `--country` | - | - | 国家 |
| `--state` | - | - | 省份 |
| `--locality` | - | - | 城市 |
| `--max-path-len` | - | -1 | CA 最大路径长度，-1 表示无限制 |
| `--path-len-zero` | - | false | 设置为终端 CA（不能签发子 CA） |

## signcert 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--ca-cert` | `--ca` | - | CA 证书文件路径（必需） |
| `--ca-key` | `--cakey` | - | CA 私钥文件路径（必需） |
| `--cert-out` | `-c` | cert.pem | 签发证书输出路径 |
| `--key-out` | `-k` | cert_key.pem | 私钥输出路径 |
| `--algorithm` | `-a` | RSA | 密钥算法 |
| `--rsa-bits` | `-b` | 2048 | RSA 密钥位数 |
| `--ecdsa-curve` | `-e` | P256 | ECDSA 曲线 |
| `--days` | `-d` | 365 | 证书有效期（天），必须大于 0 |
| `--cn` | - | localhost | 通用名称 |
| `--dns-names` | - | - | DNS 名称（逗号分隔） |
| `--ip-addrs` | - | - | IP 地址（逗号分隔） |
| `--usage` | - | server | 证书用途：server, client, codesigning, email |
| `--is-ca` | - | false | 生成中间 CA 证书 |

## certinfo 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--cert` | `-c` | - | 证书文件路径（必需） |

## gencsr 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--csr-out` | `-o` | request.csr | CSR 输出路径 |
| `--key-out` | `-k` | request_key.pem | 私钥输出路径 |
| `--algorithm` | `-a` | RSA | 密钥算法 |
| `--rsa-bits` | `-b` | 2048 | RSA 密钥位数 |
| `--ecdsa-curve` | `-e` | P256 | ECDSA 曲线 |
| `--cn` | - | localhost | 通用名称 |
| `--org` | - | - | 组织 |
| `--country` | - | - | 国家 |
| `--state` | - | - | 省份 |
| `--locality` | - | - | 城市 |
| `--dns-names` | - | - | DNS 名称（逗号分隔） |
| `--ip-addrs` | - | - | IP 地址（逗号分隔） |

## signcsr 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--ca-cert` | `--ca` | - | CA 证书文件路径（必需） |
| `--ca-key` | `--cakey` | - | CA 私钥文件路径（必需） |
| `--csr` | `-c` | - | CSR 文件路径（必需） |
| `--cert-out` | `-o` | signed.pem | 签发证书输出路径 |
| `--days` | `-d` | 365 | 证书有效期（天），必须大于 0 |
| `--usage` | - | server | 证书用途 |
| `--is-ca` | - | false | 作为 CA 证书签发 |

## gencrl 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--ca-cert` | `--ca` | - | CA 证书文件路径（必需） |
| `--ca-key` | `--cakey` | - | CA 私钥文件路径（必需） |
| `--revoke` | `-r` | - | 要吊销的证书文件路径（可多次指定） |
| `--existing` | `-e` | - | 现有 CRL 文件（新吊销会合并进去） |
| `--skip-expired` | `--se` | false | 跳过已过期的证书 |
| `--prune-days` | `--pd` | 0 | 剔除吊销超过 N 天的记录（0=不剔除），必须大于等于 0 |
| `--days` | `-d` | 30 | CRL 有效期（天），必须大于 0 |
| `--out` | `-o` | crl.pem | CRL 输出路径 |

## viewcrl 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--crl` | `-c` | - | CRL 文件路径（必需） |

## checkrevoked 参数说明

| 参数 | 别名 | 默认值 | 说明 |
|------|------|--------|------|
| `--cert` | `-c` | - | 证书文件路径（必需） |
| `--crl` | `--crl` | - | CRL 文件路径（必需） |

## Web 界面

Web 界面提供了所有 CLI 功能的图形化操作，支持中英文切换。

启动 Web 服务器后访问 `http://localhost:8866`：

- **生成根证书** - 配置算法、有效期、主题信息
- **签发证书** - 上传 CA 证书签发新证书
- **查看证书信息** - 解析并显示证书详情
- **签名/验签** - 对文本数据进行签名和验证
- **加密/解密** - 使用证书加密解密数据
- **证书链验证** - 验证证书的有效性
- **CSR 管理** - 生成 CSR 和签发 CSR
- **CRL 管理** - 生成/查看 CRL，检查证书吊销状态

## 开发

### 运行测试

```bash
go test -v ./...
```

### 代码检查

```bash
golangci-lint run
```

### 构建所有平台

```bash
# Windows (PowerShell)
.\run.ps1
# 选择 1 - 构建所有平台

# Linux/macOS
make all
```

## 项目结构

```
cert/
├── cmd/cert/          # CLI 入口
├── internal/
│   ├── cli/           # CLI 命令实现
│   └── web/           # Web 服务器和 API
├── static/            # Web 静态文件
├── run.ps1            # Windows 构建脚本
├── Makefile           # Linux/macOS 构建脚本
└── .github/workflows/ # CI/CD 配置
```

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

## 作者

- **jiaopengzi** - [Blog](https://jiaopengzi.com)
