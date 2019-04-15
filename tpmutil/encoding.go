// Copyright (c) 2018, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpmutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
)

// packWithHeader takes a header and a sequence of elements that are either of
// fixed length or slices of fixed-length types and packs them into a single
// byte array using binary.Write. It updates the CommandHeader to have the right
// length.
func packWithHeader(ch commandHeader, cmd ...interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	body, err := Pack(cmd...)
	if err != nil {
		return nil, fmt.Errorf("couldn't pack message body: %v", err)
	}
	bodySize := binary.Size(body)
	ch.Size = uint32(hdrSize + bodySize)
	header, err := Pack(ch)
	if err != nil {
		return nil, fmt.Errorf("couldn't pack message header: %v", err)
	}
	return append(header, body...), nil
}

// Pack encodes a set of elements into a single byte array, using
// encoding/binary. This means that all the elements must be encodeable
// according to the rules of encoding/binary.
//
// It has one difference from encoding/binary: it encodes byte slices with a
// prepended length, to match how the TPM encodes variable-length arrays. If
// you wish to add a byte slice without length prefix, use RawBytes.
func Pack(elts ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := packType(buf, elts...); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// packType recursively packs types the same way that encoding/binary does
// under binary.BigEndian, but with one difference: it packs a byte slice as a
// lengthPrefixSize size followed by the bytes. The function unpackType
// performs the inverse operation of unpacking slices stored in this manner and
// using encoding/binary for everything else.
func packType(buf io.Writer, elts ...interface{}) error {
	for _, e := range elts {
		v := reflect.ValueOf(e)
		//fmt.Printf("value: %#v, type: %T, ok: %v\n", e, e, ok)
		if reflect.TypeOf(e).Implements(reflect.TypeOf((*SelfMarshaler)(nil)).Elem()) {
			marshaler := e.(SelfMarshaler)
			fmt.Fprintf(os.Stderr, "Trying to Marshal %T\n", e)
			if err := marshaler.TPMMarshal(buf); err != nil {
				return err
			}
			continue
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				f := v.Field(i)
				if field := v.Field(i); field.CanAddr() {
					fmt.Printf("Can Addr is true\n")
					f = field.Addr()
				}
				if err := packType(buf, f.Interface()); err != nil {
					return err
				}
			}
		default:
			if err := binary.Write(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}
	}

	return nil
}

// Unpack is a convenience wrapper around UnpackBuf. Unpack returns the number
// of bytes read from b to fill elts and error, if any.
func Unpack(b []byte, elts ...interface{}) (int, error) {
	buf := bytes.NewBuffer(b)
	err := UnpackBuf(buf, elts...)
	read := len(b) - buf.Len()
	return read, err
}

// UnpackBuf recursively unpacks types from a reader just as encoding/binary
// does under binary.BigEndian, but with one difference: it unpacks a byte
// slice by first reading an integer with lengthPrefixSize bytes, then reading
// that many bytes. It assumes that incoming values are pointers to values so
// that, e.g., underlying slices can be resized as needed.
func UnpackBuf(buf io.Reader, elts ...interface{}) error {
	for _, e := range elts {
		v := reflect.ValueOf(e)
		k := v.Kind()
		if k != reflect.Ptr {
			return fmt.Errorf("all values passed to Unpack must be pointers, got %v", k)
		}

		if v.IsNil() {
			return errors.New("can't fill a nil pointer")
		}

		marshaler, ok := e.(SelfMarshaler)
		if ok {
			if err := marshaler.TPMUnmarshal(buf); err != nil {
				return err
			}
			continue
		}
		handles, isHandles := e.(*[]Handle)
		if isHandles {
			var tmpSize uint16
			if err := binary.Read(buf, binary.BigEndian, &tmpSize); err != nil {
				return err
			}
			size := int(tmpSize)

			// A zero size is used by the TPM to signal that certain elements
			// are not present.
			if size == 0 {
				continue
			}

			// Make len(e) match size exactly.
			if len(*handles) >= size {
				*handles = (*handles)[:size]
			} else {
				*handles = append(*handles, make([]Handle, size-len(*handles))...)
			}

			if err := binary.Read(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}
		iv := reflect.Indirect(v)
		switch iv.Kind() {
		case reflect.Struct:
			// Decompose the struct and copy over the values.
			for i := 0; i < iv.NumField(); i++ {
				if err := UnpackBuf(buf, iv.Field(i).Addr().Interface()); err != nil {
					return err
				}
			}
		case reflect.Array:
			fmt.Printf("We got an Array\n")
			fallthrough
		default:
			if err := binary.Read(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}

	}

	return nil
}
