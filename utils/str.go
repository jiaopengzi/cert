//
// FilePath    : cert\utils\str.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 字符串工具函数
//

package utils

import (
	"net"
	"strings"
)

// SplitStrTrimList 将字符串按指定分隔符拆分为字符串切片，并去除每个元素的前后空格，忽略空元素。
func SplitStrTrimList(value string, delimiter string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, delimiter)
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			result = append(result, item)
		}
	}

	return result
}

// ParseIPListFromStr 从逗号分隔的字符串解析 IP 地址列表.
func ParseIPListFromStr(value string, delimiter string) []net.IP {
	items := SplitStrTrimList(value, delimiter)
	ips := make([]net.IP, 0, len(items))

	for _, item := range items {
		if ip := net.ParseIP(item); ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips
}
