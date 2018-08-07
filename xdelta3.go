// Copyright 2018 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package xdelta

/*
// Load C library and configure build flags
#cgo LDFLAGS: -lxdelta3
#cgo lzma CFLAGS: -DSECONDARY_LZMA=1
#cgo fgk CFLAGS: -DSECONDARY_FGK=1
#cgo no-encoder CFLAGS: -DXD3_ENCODER=0
#cgo CFLAGS: -DSECONDARY_DJW=1
#ifndef SECONDARY_LZMA
#   define SECONDARY_LZMA 0
#endif
#ifndef SECONDARY_FGK
#   define SECONDARY_FGK 0
#endif

// Set window size to 16kB, equates to approx. 32kB memory usage.
#define XD3_ALLOCSIZE (1U << 16)

#include <xdelta3.h>

// These structures has to reside in the C code in order
// for the cgo checks to pass.
static xd3_stream stream;
static xd3_source source;
static xd3_config config;
static inline xd3_stream *getStream () {return &stream;}
static inline xd3_source *getSource () {return &source;}
static inline xd3_config *getConfig () {return &config;}

// Wrap C function pointers to make them accessible in Go.
// from xdelta.h :
// int xd3_decode_input (xd3_stream *);
// int xd3_encode_input (xd3_stream *);
typedef int (*codeFunc) (xd3_stream *);
// encode / decode callback
int _xd3_code(codeFunc f, xd3_stream * stream) { return f(stream); }
*/
import "C"
import (
	"io"
	"unsafe"

	"github.com/pkg/errors"
)

// Buffer allocation size
const XD3_ALLOCSIZE = C.XD3_ALLOCSIZE

/**
+--------------------------+ (io.ReadCloser - device.go (image))
|artifact.mender (patch)   |==InFile=====++
+--------------------------+             ||
+--------------------------+             || srcFile.doPatch(InFile) -> OutFile
|/dev/active-part (ro-rfs) |==srcFile====++===========++
+--------------------------+ (blockdevice - delta.go) ||
+--------------------------+                          VV     +------------------+
|/dev/inactive-part        |==OutFile=================++====>|updated partition |
+--------------------------+ (blockdevice)                   +------------------+
*/

// XdeltaCoder.flags
const (
	// compression flags
	// DJW is enabled by default.
	XD3_SECONDARY_DJW = C.XD3_SEC_DJW
	// FGK is NOT enabled by default. Enabled with fgk build tag.
	XD3_SECONDARY_FGK = C.XD3_SEC_FGK
	// LZMA depends on `lzma` build tag and the library exists on your system
	XD3_SECONDARY_LZMA = C.XD3_SEC_LZMA
	XD3_COMPLEVEL_1    = (1 << 20)
	XD3_COMPLEVEL_2    = (2 << 20)
	XD3_COMPLEVEL_3    = (3 << 20)
	XD3_COMPLEVEL_6    = (6 << 20)
	XD3_COMPLEVEL_9    = (9 << 20)
	// disable ordinary data compression
	XD3_NOCOMPRESS = C.XD3_NOCOMPRESS
	// enable adler32 checksum computation in encoder
	XD3_ADLER32 = C.XD3_ADLER32
	// skip checksum verification in decoder
	XD3_ADLER32_NOVER = C.XD3_ADLER32_NOVER
)

type XdeltaCoder struct {
	// srcFile : old file
	srcFile io.ReadSeeker
	// xdelta encode/decode flags see constant definitions above.
	flags int
	// output file
	outFile io.Writer
	// input file
	inFile io.Reader
}

// NewXdeltaCoder returns a new XdeltaCoder with a fixed source file
// and encoder/decoder flags. These flags has to be fixed if it ought
// to be used as both encoder and decoder w.r.t. the same patch.
// See flag definitions above.
func NewXdeltaCoder(src io.ReadSeeker, flags int) *XdeltaCoder {
	return &XdeltaCoder{
		srcFile: src,
		flags:   flags,
	}
}

// Decodes source and patch (in) to an updated revision (out).
// patch is the input patch to decode
// dst is the target updated file
func (x *XdeltaCoder) Decode(patch io.Reader, dst io.Writer) error {
	x.inFile = patch
	x.outFile = dst
	return x.encodeDecode(C.codeFunc(C.xd3_decode_input))
}

// Encodes source and updated revision (in) to a VCDIFF patch (out).
// target is the target updated file
// patch is the output patch to encode
func (x *XdeltaCoder) Encode(target io.Reader, patch io.Writer) error {
	x.inFile = target
	x.outFile = patch
	return x.encodeDecode(C.codeFunc(C.xd3_encode_input))
}

// encodeDecode is a general function to encode / decode a byte stream
// to / from a patch / updated revision respectively. The actual encoding
// and decoding happens in xd3_encode_input and xd3_decode_input functions
// respectively, and the preparations of the streams are completely the same
// only the meaning of "in" and "out" is swapped.
func (x *XdeltaCoder) encodeDecode(XD3_CODE C.codeFunc) error {
	var err error

	stream := C.getStream()
	source := C.getSource()
	config := C.getConfig()

	if x.srcFile == nil || x.inFile == nil || x.outFile == nil {
		return errors.New("[XdeltaCoder]: Calling decode without configuring streams {source|patch|out}.")
	}

	// Setup buffers and initiate c interface
	inBuf := make([]byte, XD3_ALLOCSIZE)

	// temporary buffer for source
	srcBuf := make([]byte, XD3_ALLOCSIZE)

	// Configure source and stream
	C.memset(unsafe.Pointer(stream), 0, C.sizeof_xd3_stream)
	C.memset(unsafe.Pointer(source), 0, C.sizeof_xd3_stream)

	C.xd3_init_config(config, C.int(x.flags))
	config.winsize = C.uint(len(inBuf))
	if C.xd3_config_stream(stream, config) != 0 {
		return errors.Errorf("[Xdelta] Error configuring stream: %s", C.GoString(stream.msg))
	}
	source.curblk = (*C.uchar)(unsafe.Pointer(&srcBuf[0]))
	source.blksize = C.uint(len(srcBuf))

	// Load first block from stream
	onblk, err := x.srcFile.Read(srcBuf)
	if err != nil {
		C.xd3_free_stream(stream)
		return errors.Wrapf(err, "Xdelta: error reading from source file")
	}
	source.onblk = C.uint(onblk)
	source.curblkno = 0

	C.xd3_set_source(stream, source)

	var ret C.int
	for {
		// get a new chunk of patch file
		inBytesRead, err := x.inFile.Read(inBuf)
		if inBytesRead < len(inBuf) {
			C.xd3_set_flags(stream, C.XD3_FLUSH|stream.flags)
			if err == io.EOF {
				err = nil
			}
		} else if err != nil {
			err = errors.Wrap(err, "[Xdelta] Error fetching input: ")
			C.xd3_close_stream(stream)
			C.xd3_free_stream(stream)
			return err
		}
		C.xd3_avail_input(stream, (*C.uchar)(unsafe.Pointer(&inBuf[0])), C.uint(inBytesRead))
		for {
			ret = C._xd3_code(XD3_CODE, stream)
			switch ret {
			case C.XD3_INPUT:
				// Need more input
				goto CONTINUE
			case C.XD3_OUTPUT:
				// Output ready
				bytesWritten, err := x.outFile.Write(C.GoBytes(unsafe.Pointer(stream.next_out),
					C.int(stream.avail_out)))
				if err != nil {
					err = errors.Wrap(err, "[Xdelta] Error writing output: ")
					C.xd3_close_stream(stream)
					C.xd3_free_stream(stream)
					return err
				} else if bytesWritten != int(stream.avail_out) {
					err = errors.Errorf("Wrote an unexpected amount "+
						"(%d of %d) through xdelta stream, ABORTING.",
						bytesWritten, int(stream.avail_out))
					C.xd3_close_stream(stream)
					C.xd3_free_stream(stream)
					return err
				}
				C.xd3_consume_output(stream)

			case C.XD3_GETSRCBLK:
				// Fetch source
				var srcBytesRead int
				_, err = x.srcFile.Seek(int64(source.blksize)*int64(source.getblkno), io.SeekStart)
				if err != nil {
					err = errors.Wrapf(err, "Xdelta: error seeking in source file")
					C.xd3_close_stream(stream)
					C.xd3_free_stream(stream)
					return err
				}
				if srcBytesRead, err = x.srcFile.Read(srcBuf); err != nil {
					if err == io.EOF {
						err = nil
					} else {
						err = errors.Wrapf(err, "Xdelta: error reading from source file")
						C.xd3_close_stream(stream)
						C.xd3_free_stream(stream)
						return err
					}
				}
				source.curblk = (*C.uchar)(unsafe.Pointer(&srcBuf[0]))
				source.onblk = C.uint(srcBytesRead)
				source.curblkno = C.ulong(source.getblkno)

				/* Noop cases */
			case C.XD3_GOTHEADER:
			case C.XD3_WINSTART:
			case C.XD3_WINFINISH:

				// Error return values
			case C.XD3_INVALID_INPUT:
				err = errors.Errorf("Xdelta error: %s [exit code: %d]."+
					" Possibly a source-patch mismatch.",
					C.GoString(stream.msg), int(ret))
				C.xd3_close_stream(stream)
				C.xd3_free_stream(stream)
				return err
			default:
				err = errors.Errorf("Xdelta error: %s [exit code: %d].",
					C.GoString(stream.msg), int(ret))
				C.xd3_close_stream(stream)
				C.xd3_free_stream(stream)
				return err
			}
		}
	CONTINUE:
		// do {...} while (inBytesRead != len(inBuf))
		if inBytesRead != len(inBuf) {
			break
		}
	}

	C.xd3_close_stream(stream)
	C.xd3_free_stream(stream)
	return nil
}
