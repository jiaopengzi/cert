---
language: go
description: Go 语言注释规则与示例
---

# Go 语言注释规则

本文件为 Go 语言的注释规范参考, 配合主 skill 使用。

## 环境与依赖版本

在处理 Go 项目时, 助理应自行执行以下操作以了解项目环境：

1. 运行 `go version` 获取当前 Go 版本。
2. 阅读项目根目录的 `go.mod` 文件, 了解：
   - `go` 指令指定的最低 Go 版本要求。
   - `require` 块中的依赖及其版本。
   - `replace` 或 `exclude` 指令（如有）。

这些信息有助于生成与项目兼容的代码和注释。

## 注释风格

- 使用 `//` 风格的单行注释。
- 函数注释以函数名开头, 后接功能描述。
- 参数说明使用 `//   - paramName, 说明...` 格式。
- 返回值说明使用 `// 返回值 type, 说明...` 格式。

## 函数注释模版

```go
// FunctionName 函数功能简述。
//   - param1, 第一个参数说明。
//   - param2, 第二个参数说明。
// 返回值 type, 返回值说明; 第二个返回值 error, 出错时非 nil。
func FunctionName(param1 Type1, param2 Type2) (Type3, error) {
    // 实现代码
}
```

## 完整示例

### 示例 1: 简单函数

```go
// Add 计算两个整数之和。
//   - a, 第一个加数。
//   - b, 第二个加数。
// 返回值 int, 两数之和。
func Add(a int, b int) int {
    return a + b
}
```

### 示例 2: 带错误返回的函数

```go
// 原注释: // SignCertificate signs a certificate using provided key.
// SignCertificate 对证书进行签名。
//   - certPEM, 待签名的证书 PEM 编码。
//   - signerKey, 用于签名的私钥对象。
// 返回值 error, 出错时非 nil。
func SignCertificate(certPEM []byte, signerKey crypto.PrivateKey) error {
    // 签名逻辑实现
    return nil
}
```

### 示例 3: 保留原注释并补充

```go
// 原注释: // Encrypt encrypts data.
// Encrypt 使用指定密钥加密数据。
//   - key, 加密密钥, 长度必须为 16, 24 或 32 字节。
//   - plaintext, 待加密的明文数据。
// 返回值 []byte, 加密后的密文; error, 出错时非 nil。
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
    // 加密逻辑
    return nil, nil
}
```

## 结构体与接口注释

```go
// Config 应用程序配置结构体。
//   - Host, 服务器主机地址。
//   - Port, 服务器端口号。
//   - Debug, 是否启用调试模式。
type Config struct {
    Host  string
    Port  int
    Debug bool
}

// Handler 请求处理器接口。
type Handler interface {
    // Handle 处理传入的请求。
    //   - ctx, 请求上下文。
    //   - req, 请求数据。
    // 返回值 Response, 响应数据; error, 出错时非 nil。
    Handle(ctx context.Context, req *Request) (*Response, error)
}
```

## 静态检查工具

- 推荐使用 `golangci-lint` 进行代码检查。

运行检查命令:

```bash
golangci-lint run ./...
```

---

注: 本文件为 Go 语言特定规则, 通用规则请参阅主 `SKILL.md`。
