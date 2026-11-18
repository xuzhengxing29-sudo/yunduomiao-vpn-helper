//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectSecret(plain []byte) ([]byte, error) {
	var in windows.DataBlob
	if len(plain) > 0 {
		in.Size = uint32(len(plain))
		in.Data = &plain[0]
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	}()
	buf := unsafe.Slice(out.Data, out.Size)
	res := make([]byte, len(buf))
	copy(res, buf)
	return res, nil
}

func unprotectSecret(enc []byte) ([]byte, error) {
	var in windows.DataBlob
	if len(enc) > 0 {
		in.Size = uint32(len(enc))
		in.Data = &enc[0]
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	}()
	buf := unsafe.Slice(out.Data, out.Size)
	res := make([]byte, len(buf))
	copy(res, buf)
	return res, nil
}
