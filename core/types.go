//
// FilePath    : cert\core\types.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书相关类型定义
//

package core

import (
	"crypto/x509"
	"math/big"
	"net"
	"time"
)

// Subject 描述 X.509 证书主题字段.
type Subject struct {
	Country            string // 国家
	State              string // 省份
	Locality           string // 城市
	Organization       string // 组织
	OrganizationalUnit string // 组织单位
	CommonName         string // 通用名称
}

// KeyAlgorithm 密钥算法类型.
type KeyAlgorithm string

// KeyAlgorithm 枚举值.
const (
	KeyAlgorithmRSA     KeyAlgorithm = "RSA"
	KeyAlgorithmECDSA   KeyAlgorithm = "ECDSA"
	KeyAlgorithmEd25519 KeyAlgorithm = "Ed25519"
)

// ECDSACurve ECDSA 曲线类型.
type ECDSACurve string

// ECDSACurve 枚举值.
const (
	CurveP256 ECDSACurve = "P256"
	CurveP384 ECDSACurve = "P384"
	CurveP521 ECDSACurve = "P521"
)

// CertUsage 证书用途.
type CertUsage int

const (
	// UsageServer 服务器认证.
	UsageServer CertUsage = 1 << iota
	// UsageClient 客户端认证.
	UsageClient
	// UsageCodeSigning 代码签名.
	UsageCodeSigning
	// UsageEmailProtection 邮件保护.
	UsageEmailProtection
)

// SANConfig 主题备用名称配置.
type SANConfig struct {
	DNSNames    []string // DNS 名称列表
	IPAddresses []net.IP // IP 地址列表
	EmailAddrs  []string // 电子邮件地址列表
	URIs        []string // URI 列表
}

// CACertConfig CA 证书生成参数.
type CACertConfig struct {
	RSAKeyBits   int          // [RSA] 私钥位数(默认2048, 可选4096)
	DaysValid    int          // 证书有效期(天)
	Subject      Subject      // 证书主题信息
	Key          string       // 私钥
	Cert         string       // 证书
	KeyAlgorithm KeyAlgorithm // 密钥算法(RSA/ECDSA/Ed25519)
	ECDSACurve   ECDSACurve   // [ECDSA] 曲线(P256/P384/P521)
	PathLenZero  bool         // 是否为终端 CA(不能签发下级 CA)
	MaxPathLen   int          // 最大路径长度(-1 表示无限制), 用于限制下级 CA 签发能力
}

// CASignedCertConfig 由 CA 签发的证书配置.
type CASignedCertConfig struct {
	CACert       string       // CA 证书
	CAKey        string       // CA 私钥
	Name         string       // 证书名称
	Subject      Subject      // 证书主题
	Cert         string       // 证书
	Key          string       // 私钥
	DaysValid    int          // 证书有效期(天)
	RSAKeyBits   int          // [RSA] 私钥位数(默认2048, 可选4096)
	KeyAlgorithm KeyAlgorithm // 密钥算法(RSA/ECDSA/Ed25519)
	ECDSACurve   ECDSACurve   // [ECDSA] 曲线(P256/P384/P521)
	SAN          SANConfig    // 主题备用名称
	Usage        CertUsage    // 证书用途(服务器/客户端等)
	IsCA         bool         // 是否为中间 CA
	MaxPathLen   int          // 中间 CA 最大路径长度
}

// CSRConfig 证书签名请求配置.
type CSRConfig struct {
	Subject      Subject      // 证书主题
	RSAKeyBits   int          // [RSA] 私钥位数(默认2048)
	KeyAlgorithm KeyAlgorithm // 密钥算法(RSA/ECDSA/Ed25519)
	ECDSACurve   ECDSACurve   // [ECDSA] 曲线(P256/P384/P521)
	SAN          SANConfig    // 主题备用名称
	CSR          string       // 生成的 CSR(PEM 格式)
	Key          string       // 生成的私钥(PEM 格式)
}

// CSRSignConfig CSR 签发配置.
type CSRSignConfig struct {
	CACert    string    // CA 证书
	CAKey     string    // CA 私钥
	CSR       string    // 待签发的 CSR
	DaysValid int       // 证书有效期(天)
	Usage     CertUsage // 证书用途
	IsCA      bool      // 是否为 CA 证书
	Cert      string    // 签发的证书
}

// CRLConfig 证书吊销列表配置.
type CRLConfig struct {
	CACert         string     // CA 证书
	CAKey          string     // CA 私钥
	RevokedCerts   []string   // 要吊销的证书列表(PEM 格式)
	ExistingCRL    string     // 现有的 CRL(PEM 格式), 新吊销会合并进去
	SkipExpired    bool       // 跳过已过期的证书(不吊销已过期的证书)
	PruneAfterDays int        // 剔除吊销超过 N 天的历史记录(0 表示不剔除)
	DaysValid      int        // CRL 有效期(天)
	CRL            string     // 生成的 CRL(PEM 格式)
	ThisUpdate     time.Time  // 本次更新时间
	NextUpdate     time.Time  // 下次更新时间
	RevokedSerials []*big.Int // 已吊销证书序列号列表
	SkippedExpired int        // 跳过的已过期证书数量(输出)
	PrunedCount    int        // 剔除的历史记录数量(输出)
}

// crlBuilder 用于构建 CRL 的内部状态.
type crlBuilder struct {
	cfg          *CRLConfig
	revokedCerts []x509.RevocationListEntry
	serialSet    map[string]bool
	crlNumber    *big.Int
	now          time.Time
}

// RevokedCertInfo 吊销证书信息.
type RevokedCertInfo struct {
	SerialNumber   *big.Int  // 证书序列号
	RevocationTime time.Time // 吊销时间
	Reason         int       // 吊销原因
}

// CertValidateConfig 证书验证配置.
type CertValidateConfig struct {
	Cert            string    // 待验证的证书
	CACert          string    // CA 证书(可选, 用于验证签名)
	IntermediateCAs []string  // 中间 CA 证书链
	CheckTime       time.Time // 验证时间点(零值表示当前时间)
	DNSName         string    // 验证 DNS 名称
	Usage           CertUsage // 验证用途
}

// CertChainConfig 证书链配置.
type CertChainConfig struct {
	EndEntityCert   string   // 终端实体证书
	IntermediateCAs []string // 中间 CA 证书列表(从低到高排序)
	RootCA          string   // 根 CA 证书
	FullChain       string   // 完整证书链(PEM 格式)
}

// CertInfo 证书信息结构.
type CertInfo struct {
	SerialNumber string    // 证书序列号
	Subject      string    // 证书主题
	Issuer       string    // 证书颁发者
	NotBefore    time.Time // 生效时间
	NotAfter     time.Time // 过期时间
	IsCA         bool      // 是否为 CA 证书
	KeyAlgorithm string    // 密钥算法
	DNSNames     []string  // DNS 名称列表
	IPAddresses  []string  // IP 地址列表
	ExtKeyUsages []string  // 扩展密钥用途
}

// PEMBlockType PEM 块类型.
type PEMBlockType string

// PEMBlockType 枚举值.
const (
	PEMBlockCertificate        PEMBlockType = "CERTIFICATE"         // X.509 证书.
	PEMBlockPrivateKey         PEMBlockType = "PRIVATE KEY"         // PKCS#8 私钥.
	PEMBlockRSAPrivateKey      PEMBlockType = "RSA PRIVATE KEY"     // PKCS#1 RSA 私钥.
	PEMBlockECPrivateKey       PEMBlockType = "EC PRIVATE KEY"      // SEC 1 EC 私钥.
	PEMBlockPublicKey          PEMBlockType = "PUBLIC KEY"          // PKIX 公钥.
	PEMBlockCertificateRequest PEMBlockType = "CERTIFICATE REQUEST" // 证书签名请求.
	PEMBlockCRL                PEMBlockType = "X509 CRL"            // 证书吊销列表.
)
