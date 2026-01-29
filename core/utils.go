//
// FilePath    : cert\core\utils.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 证书工具函数
//

package core

import utils "github.com/jiaopengzi/go-utils"

// ParseSANFromStr 从逗号分隔的字符串解析 SAN 配置.
func ParseSANFromStr(dnsNames, ipAddrs string) SANConfig {
	return SANConfig{
		DNSNames:    utils.SplitStrTrimList(dnsNames, ","),
		IPAddresses: utils.ParseIPListFromStr(ipAddrs, ","),
	}
}
