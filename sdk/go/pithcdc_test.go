// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithcdc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// repoRoot resolves the repository root relative to this package
// (sdk/go -> sdk -> repo root), the anchor for reference.json.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "reference.json")); err != nil || st.IsDir() {
		t.Fatalf("reference.json not found at %s", root)
	}
	return root
}

// vector mirrors one committed reference.json entry.
type vector struct {
	Name  string `json:"name"`
	Input struct {
		Kind    string `json:"kind"`
		SeedHex string `json:"seed_hex"`
		Length  int    `json:"length"`
	} `json:"input"`
	Params struct {
		MinSize int    `json:"min_size"`
		AvgSize int    `json:"avg_size"`
		MaxSize int    `json:"max_size"`
		Level   uint32 `json:"level"`
	} `json:"params"`
	Chunks [][3]interface{} `json:"chunks"`
}

// reference parses the committed reference.json.
func reference(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Vectors
}

const mask64 = uint64(0xffffffffffffffff)

// splitmix64Bytes regenerates the corpus's splitmix64 recipe:
// little-endian words, the last partial word carrying the low bytes.
func splitmix64Bytes(seed uint64, length int) []byte {
	out := make([]byte, length)
	state := seed
	for pos := 0; pos < length; pos += 8 {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		var word [8]byte
		for i := range 8 {
			word[i] = byte(z >> (8 * uint(i)))
		}
		take := 8
		if length-pos < take {
			take = length - pos
		}
		copy(out[pos:pos+take], word[:take])
	}
	return out
}

// buildInput mirrors tools/gen-reference build_input exactly.
func buildInput(kind, seedHex string, length int) []byte {
	switch kind {
	case "splitmix64":
		var seed uint64
		if _, err := fmt.Sscanf(seedHex, "%x", &seed); err != nil {
			panic(err)
		}
		return splitmix64Bytes(seed, length)
	case "zeros":
		return make([]byte, length)
	case "fill-ff":
		out := make([]byte, length)
		for i := range out {
			out[i] = 0xff
		}
		return out
	case "sawtooth":
		out := make([]byte, length)
		for i := range out {
			out[i] = byte((i*7 + 13) % 256)
		}
		return out
	default:
		panic("unknown corpus kind " + kind)
	}
}

// chunkRecord is one committed [offset, length, "fingerprint-hex"] row.
type chunkRecord struct {
	offset int
	length int
	hash   string
}

// recordedChunks decodes the committed chunk rows.
func recordedChunks(v vector) []chunkRecord {
	rows := make([]chunkRecord, len(v.Chunks))
	for i, triple := range v.Chunks {
		offset, _ := triple[0].(float64)
		length, _ := triple[1].(float64)
		hash, _ := triple[2].(string)
		rows[i] = chunkRecord{offset: int(offset), length: int(length), hash: hash}
	}
	return rows
}

// TestReferenceVectorsHexExact replays every committed reference.json
// vector through the cdylib and compares exactly: the chunk count,
// every (offset, length) boundary and every fingerprint formatted
// %016x — the same vectors the Rust gen-reference verify gate and the
// Python/Node SDKs check.
func TestReferenceVectorsHexExact(t *testing.T) {
	for _, v := range reference(t) {
		t.Run(v.Name, func(t *testing.T) {
			data := buildInput(v.Input.Kind, v.Input.SeedHex, v.Input.Length)
			got, err := ChunkData(data, v.Params.MinSize, v.Params.AvgSize, v.Params.MaxSize, v.Params.Level)
			if err != nil {
				t.Fatalf("ChunkData(%s): %v", v.Name, err)
			}
			want := recordedChunks(v)
			if len(got) != len(want) {
				t.Fatalf("%s: chunk count %d, want %d", v.Name, len(got), len(want))
			}
			for i := range got {
				if got[i].Offset != uint64(want[i].offset) {
					t.Errorf("%s chunk %d: offset %d, want %d", v.Name, i, got[i].Offset, want[i].offset)
				}
				if got[i].Length != uint64(want[i].length) {
					t.Errorf("%s chunk %d: length %d, want %d", v.Name, i, got[i].Length, want[i].length)
				}
				if fp := fmt.Sprintf("%016x", got[i].Hash); fp != want[i].hash {
					t.Errorf("%s chunk %d: hash %s, want %s", v.Name, i, fp, want[i].hash)
				}
			}
		})
	}
}

// TestPinnedFirstChunk pins splitmix64-1mib-2k8k32k-l2's first chunk —
// re-derived by the Rust unit tests — so the binding fails loudly even
// if reference.json were regenerated wrongly.
func TestPinnedFirstChunk(t *testing.T) {
	data := splitmix64Bytes(0x5eed5eed5eed5eed, 1<<20)
	got, err := ChunkData(data, 2048, 8192, 32768, Level2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no chunks")
	}
	if got[0].Offset != 0 || got[0].Length != 2386 {
		t.Fatalf("first chunk %d/%d, want 0/2386", got[0].Offset, got[0].Length)
	}
	if fp := fmt.Sprintf("%016x", got[0].Hash); fp != "dead20b04c882e33" {
		t.Fatalf("first fingerprint %s, want dead20b04c882e33", fp)
	}
}

// TestRefusalsAreStatusesNotCrashes checks the refusal paths: a status
// code, never a crash.
func TestRefusalsAreStatusesNotCrashes(t *testing.T) {
	data := make([]byte, 4096)

	// Unknown level wire code.
	if _, err := ChunkData(data, 2048, 8192, 32768, 9); err == nil {
		t.Fatal("unknown level: want error")
	} else if ffi, ok := err.(*FfiError); !ok || ffi.Status != StatusInvalid {
		t.Fatalf("unknown level: want StatusInvalid, got %v", err)
	}

	// Below-range min_size.
	if _, err := ChunkData(data, 32, 8192, 32768, Level2); err == nil {
		t.Fatal("below-range min: want error")
	} else if ffi, ok := err.(*FfiError); !ok || ffi.Status != StatusRejected {
		t.Fatalf("below-range min: want StatusRejected, got %v", err)
	}

	// avg < min.
	if _, err := ChunkData(data, 8192, 2048, 32768, Level2); err == nil {
		t.Fatal("avg < min: want error")
	} else if ffi, ok := err.(*FfiError); !ok || ffi.Status != StatusRejected {
		t.Fatalf("avg < min: want StatusRejected, got %v", err)
	}

	// A null data pointer with a non-zero length, at the ffi layer.
	var out *uint64
	var outLen uintptr
	status, err := ffiChunk(mustCdylib(t), nil, 16, 2048, 8192, 32768, Level2, &out, &outLen)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusInvalid {
		t.Fatalf("null data: want StatusInvalid, got %d", status)
	}

	// An empty input is legal and yields zero chunks.
	empty, err := ChunkData(nil, 2048, 8192, 32768, Level2)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty input: got %v, %v", empty, err)
	}
}

// mustCdylib resolves the cdylib path for the white-box ffi-layer tests.
func mustCdylib(t *testing.T) string {
	t.Helper()
	p, err := FindCdylib()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
