//
// FilePath    : cert\cmd\cert\main_test.go
// Author      : jiaopengzi
// Blog        : https://jiaopengzi.com
// Copyright   : Copyright (c) 2026 by jiaopengzi, All Rights Reserved.
// Description : applyBuildInfo 单元测试
//

package main

import (
	"runtime/debug"
	"testing"
)

func TestApplyBuildInfo_PopulatesWhenDefaults(t *testing.T) {
	// 保存并在结束时恢复全局变量
	origV, origC, origT := Version, Commit, BuildTime
	defer func() {
		Version, Commit, BuildTime = origV, origC, origT
	}()

	Version = "dev"
	Commit = "unknown"
	BuildTime = "unknown"

	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef123"},
			{Key: "vcs.time", Value: "2025-01-01T12:00:00Z"},
		},
	}

	applyBuildInfo(bi)

	if Version != "v1.2.3" {
		t.Fatalf("expected Version v1.2.3, got %s", Version)
	}
	if Commit != "abcdef123" {
		t.Fatalf("expected Commit abcdef123, got %s", Commit)
	}
	if BuildTime != "2025-01-01T12:00:00Z" {
		t.Fatalf("expected BuildTime 2025-01-01T12:00:00Z, got %s", BuildTime)
	}
}

func TestApplyBuildInfo_DoesNotOverrideLDFlags(t *testing.T) {
	origV, origC, origT := Version, Commit, BuildTime
	defer func() {
		Version, Commit, BuildTime = origV, origC, origT
	}()

	// 模拟通过 ldflags 注入的值
	Version = "v2.0.0"
	Commit = "preldhash"
	BuildTime = "2025-02-02T00:00:00Z"

	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef123"},
			{Key: "vcs.time", Value: "2025-01-01T12:00:00Z"},
		},
	}

	applyBuildInfo(bi)

	if Version != "v2.0.0" {
		t.Fatalf("expected Version v2.0.0 (ldflags), got %s", Version)
	}
	if Commit != "preldhash" {
		t.Fatalf("expected Commit preldhash (ldflags), got %s", Commit)
	}
	if BuildTime != "2025-02-02T00:00:00Z" {
		t.Fatalf("expected BuildTime 2025-02-02T00:00:00Z (ldflags), got %s", BuildTime)
	}
}

func TestApplyBuildInfo_NilDoesNothing(t *testing.T) {
	origV, origC, origT := Version, Commit, BuildTime
	defer func() {
		Version, Commit, BuildTime = origV, origC, origT
	}()

	Version = "dev"
	Commit = "unknown"
	BuildTime = "unknown"

	applyBuildInfo(nil)

	if Version != "dev" || Commit != "unknown" || BuildTime != "unknown" {
		t.Fatalf("expected defaults unchanged, got %s %s %s", Version, Commit, BuildTime)
	}
}
