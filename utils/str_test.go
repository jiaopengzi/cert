//
// FilePath    : cert\utils\str_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : 字符串工具函数单元测试
//

package utils

import (
	"testing"
)

// ============================================
// 工具函数测试
// ============================================

// TestSplitStrTrimList 测试逗号分隔列表解析.
func TestSplitStrTrimList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "正常输入",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "带空格",
			input:    "a, b, c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "空字符串",
			input:    "",
			expected: nil,
		},
		{
			name:     "只有空格",
			input:    "   ",
			expected: nil,
		},
		{
			name:     "单个元素",
			input:    "single",
			expected: []string{"single"},
		},
		{
			name:     "带空元素",
			input:    "a,,b",
			expected: []string{"a", "b"},
		},
		{
			name:     "前后空格",
			input:    "  a  ,  b  ,  c  ",
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitStrTrimList(tt.input, ",")

			if len(result) != len(tt.expected) {
				t.Errorf("期望 %d 个元素, 实际 %d 个", len(tt.expected), len(result))
				return
			}

			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("索引 %d: 期望 %s, 实际 %s", i, tt.expected[i], v)
				}
			}
		})
	}
}

// TestParseIPList 测试 IP 列表解析.
func TestParseIPList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "IPv4 地址",
			input:    "127.0.0.1,192.168.1.1",
			expected: 2,
		},
		{
			name:     "IPv6 地址",
			input:    "::1,fe80::1",
			expected: 2,
		},
		{
			name:     "混合地址",
			input:    "127.0.0.1,::1",
			expected: 2,
		},
		{
			name:     "无效地址被忽略",
			input:    "127.0.0.1,invalid,192.168.1.1",
			expected: 2,
		},
		{
			name:     "空字符串",
			input:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPListFromStr(tt.input, ",")

			if len(result) != tt.expected {
				t.Errorf("期望 %d 个 IP, 实际 %d 个", tt.expected, len(result))
			}
		})
	}
}
