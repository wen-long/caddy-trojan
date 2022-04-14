package utils

import (
	"bufio"
	"net"
	"unsafe"
)

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&s)))), len(s))
}

func RewindConn(conn net.Conn, reader *bufio.Reader, line string) net.Conn {
	return NewRawConn(conn, reader, line)
}
