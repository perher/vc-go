/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package maphelpers

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	josejson "github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
)

func decodeWithNumericDateHook(t *testing.T, input map[string]any, out any) error {
	t.Helper()

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           out,
		TagName:          "json",
		Squash:           true,
		WeaklyTypedInput: true,
		DecodeHook:       JSONNumberToJwtNumericDate(),
	})
	require.NoError(t, err)

	return d.Decode(input)
}

func TestJSONNumberToJwtNumericDate(t *testing.T) {
	expected := *jwt.NewNumericDate(time.Unix(1700000000, 0))

	t.Run("json.Number into *jwt.NumericDate", func(t *testing.T) {
		var out struct {
			IssuedAt *jwt.NumericDate `json:"iat"`
		}

		require.NoError(t, decodeWithNumericDateHook(t, map[string]any{"iat": json.Number("1700000000.5")}, &out))
		require.NotNil(t, out.IssuedAt)
		require.Equal(t, expected, *out.IssuedAt)
	})

	t.Run("json.Number into jwt.NumericDate", func(t *testing.T) {
		var out struct {
			IssuedAt jwt.NumericDate `json:"iat"`
		}

		require.NoError(t, decodeWithNumericDateHook(t, map[string]any{"iat": json.Number("1700000000.5")}, &out))
		require.Equal(t, expected, out.IssuedAt)
	})

	t.Run("json.Number in exponent form into jwt.Claims", func(t *testing.T) {
		var claims jwt.Claims

		require.NoError(t, decodeWithNumericDateHook(t, map[string]any{"exp": json.Number("1.7e9")}, &claims))
		require.NotNil(t, claims.Expiry)
		require.Equal(t, expected, *claims.Expiry)
	})

	// Parsed JWT payloads carry go-jose's json.Number, which mapstructure cannot decode into an int on its own.
	t.Run("go-jose json.Number in exponent form into *jwt.NumericDate", func(t *testing.T) {
		var out struct {
			IssuedAt *jwt.NumericDate `json:"iat"`
		}

		require.NoError(t, decodeWithNumericDateHook(t, map[string]any{"iat": josejson.Number("1.7e+09")}, &out))
		require.NotNil(t, out.IssuedAt)
		require.Equal(t, expected, *out.IssuedAt)
	})

	t.Run("go-jose json.Number in exponent form into jwt.Claims", func(t *testing.T) {
		var claims jwt.Claims

		require.NoError(t, decodeWithNumericDateHook(t, map[string]any{
			"exp": josejson.Number("1.7e+09"),
			"iat": josejson.Number("1.7e+09"),
			"nbf": josejson.Number("1.7e+09"),
		}, &claims))
		require.Equal(t, expected, *claims.Expiry)
		require.Equal(t, expected, *claims.IssuedAt)
		require.Equal(t, expected, *claims.NotBefore)
	})

	hook := JSONNumberToJwtNumericDate()
	jsonNumberType := reflect.TypeFor[json.Number]()
	numericDatePtrType := reflect.TypeFor[*jwt.NumericDate]()

	t.Run("invalid json.Number into *jwt.NumericDate", func(t *testing.T) {
		_, err := hook(jsonNumberType, numericDatePtrType, json.Number("not-a-number"))
		require.Error(t, err)
	})

	t.Run("hook returns the exact target type", func(t *testing.T) {
		res, err := hook(jsonNumberType, numericDatePtrType, json.Number("1700000000"))
		require.NoError(t, err)
		require.IsType(t, (*jwt.NumericDate)(nil), res)

		res, err = hook(reflect.TypeFor[josejson.Number](), reflect.TypeFor[jwt.NumericDate](), josejson.Number("1.7e+09"))
		require.NoError(t, err)
		require.Equal(t, expected, res)
	})

	t.Run("other target types are left untouched", func(t *testing.T) {
		data := json.Number("1700000000")

		for _, target := range []reflect.Type{
			reflect.TypeFor[string](),
			reflect.TypeFor[int64](),
			reflect.TypeFor[jwt.Claims](),
		} {
			res, err := hook(jsonNumberType, target, data)
			require.NoError(t, err)
			require.Equal(t, data, res)
		}
	})

	t.Run("non json.Number input is left untouched", func(t *testing.T) {
		res, err := hook(reflect.TypeFor[float64](), numericDatePtrType, float64(1700000000))
		require.NoError(t, err)
		require.InDelta(t, float64(1700000000), res, 0)
	})
}
