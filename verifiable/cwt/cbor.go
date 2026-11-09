/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cwt

import (
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// CBOR initial byte layout (RFC 8949, section 3): the top 3 bits are the major type,
// the low 5 bits are the additional information.
const (
	cborMajorTypeShift = 5
	cborMajorTypeBstr  = 2
	cborAddInfoMask    = 0x1f

	// Additional information values below cborAddInfoUint8 are the argument itself; these say that
	// the argument follows in the next 1, 2, 4 or 8 bytes.
	cborAddInfoUint8  = 24
	cborAddInfoUint16 = 25
	cborAddInfoUint32 = 26
	cborAddInfoUint64 = 27
)

// Pre-configured modes for CBOR encoding and decoding.
var (
	encMode                  cbor.EncMode //nolint:gochecknoglobals
	decModeWithTagsForbidden cbor.DecMode //nolint:gochecknoglobals
)

func init() { // nolint:gochecknoinits
	var err error

	// init encode mode
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic, // sort map keys
		IndefLength: cbor.IndefLengthForbidden,  // no streaming
	}

	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}

	// init decode mode
	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
	}
	decOpts.TagsMd = cbor.TagsForbidden
	decModeWithTagsForbidden, err = decOpts.DecMode()

	if err != nil {
		panic(err)
	}
}

// deterministicBinaryString converts a bstr into the deterministic encoding.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9052.html#section-9
func deterministicBinaryString(data cbor.RawMessage) (cbor.RawMessage, error) { //nolint:gocyclo
	if len(data) == 0 {
		return nil, io.EOF
	}

	if data[0]>>cborMajorTypeShift != cborMajorTypeBstr {
		return nil, errors.New("cbor: require bstr type")
	}

	// fast path: return immediately if bstr is already deterministic
	if err := decModeWithTagsForbidden.Valid(data); err != nil {
		return nil, err
	}

	ai := data[0] & cborAddInfoMask
	if ai < cborAddInfoUint8 {
		return data, nil
	}

	switch ai {
	case cborAddInfoUint8:
		if data[1] >= cborAddInfoUint8 {
			return data, nil
		}
	case cborAddInfoUint16:
		if data[1] != 0 {
			return data, nil
		}
	case cborAddInfoUint32:
		if data[1] != 0 || data[2] != 0 {
			return data, nil
		}
	case cborAddInfoUint64:
		if data[1] != 0 || data[2] != 0 || data[3] != 0 || data[4] != 0 {
			return data, nil
		}
	}

	// slow path: convert by re-encoding
	// error checking is not required since `data` has been validataed
	var s []byte

	err := decModeWithTagsForbidden.Unmarshal(data, &s)
	if err != nil {
		return nil, err
	}

	return encMode.Marshal(s)
}
