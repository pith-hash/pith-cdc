// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithcdc provides Go bindings for the pith-cdc Rust cdylib:
// FastCDC content-defined chunking.
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The FFI surface is one chunking operation plus one free:
// pith_cdc_chunk runs the FastCDC scan over a byte slice and hands back
// a flat (offset, length, hash) triple buffer (24 bytes per chunk), and
// pith_cdc_free releases the handed-out buffer.
package pithcdc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer, or a
	// level code the ABI does not define — only 0..=3 exist).
	StatusInvalid int32 = -1
	// StatusRejected: the core chunker refused the parameters (a size
	// outside its range, or a min <= avg <= max violation).
	StatusRejected int32 = -2
)

// Normalization-level wire codes (the ABI defines 0..=3 only).
const (
	// Level0: no normalization, the widest chunk-size spread.
	Level0 uint32 = 0
	// Level1: one bit of normalization.
	Level1 uint32 = 1
	// Level2: the paper's sweet spot and the crate default.
	Level2 uint32 = 2
	// Level3: approaching fixed-size chunking.
	Level3 uint32 = 3
)

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_cdc.dll", "libpith_cdc.so", "libpith_cdc.dylib"}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "parameters rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithcdc: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithcdc: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// Chunk is one content-defined chunk: a (Offset, Length) span plus the
// Gear fingerprint value at the cut point (Hash — a rolling
// fingerprint, not a digest).
type Chunk struct {
	// Offset is the byte offset of the chunk start within the source.
	Offset uint64
	// Length is the chunk length in bytes.
	Length uint64
	// Hash is the Gear fingerprint as of the end of the chunk.
	Hash uint64
}

// ChunkData chunks data with FastCDC and returns the chunk boundaries.
//
// minSize/avgSize/maxSize are validated by the Rust core (the spec's
// defaults are 2048/8192/32768); level is one of the Level* wire
// codes. An empty slice is legal and returns no chunks.
func ChunkData(data []byte, minSize, avgSize, maxSize int, level uint32) ([]Chunk, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	var out *uint64
	var outLen uintptr
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiChunk(libPath, dataPtr, len(data), minSize, avgSize, maxSize, level, &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_cdc_chunk", Status: status}
	}
	words := make([]uint64, outLen/8)
	copy(words, unsafe.Slice(out, outLen/8))
	ffiFree(libPath, out, outLen)
	chunks := make([]Chunk, len(words)/3)
	for i := range chunks {
		chunks[i] = Chunk{Offset: words[i*3], Length: words[i*3+1], Hash: words[i*3+2]}
	}
	return chunks, nil
}
