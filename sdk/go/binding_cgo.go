// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && cgo

package pithcdc

/*
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*pith_chunk_fn)(const uint8_t *, size_t, size_t, size_t, size_t,
                                 uint32_t, uint64_t **, size_t *);
typedef void (*pith_free_fn)(uint64_t *, size_t);

static int32_t pith_call_chunk(void *fn, const uint8_t *data, size_t len,
                               size_t min_size, size_t avg_size, size_t max_size,
                               uint32_t level, uint64_t **out, size_t *out_len) {
    return ((pith_chunk_fn)fn)(data, len, min_size, avg_size, max_size, level, out, out_len);
}

static void pith_call_free(void *fn, uint64_t *ptr, size_t len) {
    ((pith_free_fn)fn)(ptr, len);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ffiSymbols resolves both exported symbols of one open cdylib handle.
func ffiSymbols(handle unsafe.Pointer, libPath string) (chunk, freeSym unsafe.Pointer, err error) {
	for _, name := range []string{"pith_cdc_chunk", "pith_cdc_free"} {
		cName := C.CString(name)
		sym := C.dlsym(handle, cName)
		C.free(unsafe.Pointer(cName))
		if sym == nil {
			return nil, nil, fmt.Errorf("pithcdc: symbol %s missing from %s", name, libPath)
		}
		if name == "pith_cdc_chunk" {
			chunk = sym
		} else {
			freeSym = sym
		}
	}
	return chunk, freeSym, nil
}

// openCdylib dlopens libPath with error text surfaced verbatim.
func openCdylib(libPath string) (unsafe.Pointer, error) {
	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		msg := "unknown dlopen failure"
		if e := C.dlerror(); e != nil {
			msg = C.GoString(e)
		}
		return nil, fmt.Errorf("pithcdc: dlopen(%s): %s", libPath, msg)
	}
	return handle, nil
}

// ffiChunk opens the cdylib, resolves pith_cdc_chunk and calls it. The
// handle is released before returning; repeated calls reuse the
// loader's own refcount.
func ffiChunk(libPath string, data *byte, n int, minSize, avgSize, maxSize int, level uint32, out **uint64, outLen *uintptr) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)

	chunkSym, _, err := ffiSymbols(handle, libPath)
	if err != nil {
		return 0, err
	}
	var cOut *C.uint64_t
	var cLen C.size_t
	var dataPtr *C.uint8_t
	if data != nil {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(data))
	}
	rc := C.pith_call_chunk(chunkSym, dataPtr, C.size_t(n),
		C.size_t(minSize), C.size_t(avgSize), C.size_t(maxSize), C.uint32_t(level),
		&cOut, &cLen)
	*out = (*uint64)(unsafe.Pointer(cOut))
	*outLen = uintptr(cLen)
	return int32(rc), nil
}

// ffiFree releases a buffer handed out by ffiChunk. Null is accepted
// (the cdylib ignores it), matching the C contract.
func ffiFree(libPath string, ptr *uint64, n uintptr) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	defer C.dlclose(handle)
	if chunkSym, freeSym, err := ffiSymbols(handle, libPath); err == nil {
		_ = chunkSym
		C.pith_call_free(freeSym, (*C.uint64_t)(unsafe.Pointer(ptr)), C.size_t(n))
	}
}
