# Changelog

本文件将记录本项目的所有重要变更。

该格式基于 [Keep a Changelog](https://keepachangelog.com),
本项目遵循 [语义化版本控制](https://semver.org/spec/v2.0.0.html)。

## [1.0.0] - 2026-01-28

### Added

- 统一的证书工具二进制 (`cert.exe`)
    - `version` - 显示版本号
    - `genrootca` - 生成根证书和私钥
    - `signcert` - 使用 CA 签发新证书
    - `sign` - 使用私钥对数据签名
    - `verify` - 使用证书验证签名
    - `encrypt` - 使用证书公钥加密
    - `decrypt` - 使用私钥解密
    - `validatechain` - 验证证书链
    - `web` - 启动 Web 服务器（默认端口 8866）
    - 所有命令均支持中英文帮助说明

- Web 界面 (`static/index.html`)
    - 提供 Web 操作界面
    - 支持所有 CLI 功能的 Web 版本
    - RESTful API 接口
    - 响应式 HTML 前端界面

### 分发说明

分发时只需要两个文件：

- `cert.exe` - 主程序二进制
- `static/index.html` - Web 界面 HTML 文件

使用方法：

```bash
# CLI 模式
./cert.exe --help
./cert.exe genrootca -c root.pem -k root_key.pem

# Web 模式（默认端口 8866）
./cert.exe web

# 指定端口
./cert.exe web -p 9000
```
