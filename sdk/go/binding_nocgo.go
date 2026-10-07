// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && !cgo

package pithcdc

import "fmt"

// ffiChunk is unavailable without cgo on unix: there is no pure-Go
// dlopen in the standard library. Build with CGO_ENABLED=1 (the CD
// pipeline always does).
func ffiChunk(string, *byte, int, int, int, int, uint32, **uint64, *uintptr) (int32, error) {
	return 0, fmt.Errorf("pithcdc: cgo is required to load the cdylib on this platform (build with CGO_ENABLED=1)")
}

// ffiFree mirrors the unavailable chunk.
func ffiFree(string, *uint64, uintptr) {}
