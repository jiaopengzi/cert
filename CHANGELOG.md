# Changelog

本文件将记录本项目的所有重要变更。

该格式基于 [Keep a Changelog](https://keepachangelog.com),
本项目遵循 [语义化版本控制](https://semver.org/spec/v2.0.0.html)。

<a name="v0.2.0"></a>

## [v0.2.0] - 2026-01-29

### ♻️ Refactor

- **core:** 将证书的核心功能从 utils 直接抽离到 core

### ✨ Feat

- 增加 crl 追加和移除, 天数必要检验
- 增加 crl csr 和证书查看

### 🎨 Style

- 主题调整

### 📝 Docs

- 增加版本写入
- 配置调整

### 📦 Build

- 更新依赖
- 工程化配置修改
- 将 skill 抽离到工作区共享

### 🔧 Chore

- lint 规则
- skill 优化

<a name="v0.1.1"></a>

## [v0.1.1] - 2026-01-28

### 🐞 Fix

- 数据类型统一
- 对齐依赖

<a name="v0.1.0"></a>

## [v0.1.0] - 2026-01-28

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

[v0.2.0]: https://github.com/jiaopengzi/cert/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/jiaopengzi/cert/compare/v0.1.0...v0.1.1
