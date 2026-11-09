/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package maphelpers

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"
)

// JSONNumberToJwtNumericDate hook for mapstructure library to decode json.Number to jwt.NumericDate.
// Both jwt.NumericDate and *jwt.NumericDate targets are supported. The source is matched by type name, so both
// encoding/json.Number and go-jose's json.Number (used for parsed JWT payloads) are handled.
func JSONNumberToJwtNumericDate() mapstructure.DecodeHookFuncType {
	numericDateType := reflect.TypeFor[jwt.NumericDate]()
	numericDatePtrType := reflect.TypeFor[*jwt.NumericDate]()

	return func(
		f reflect.Type,
		t reflect.Type,
		data any,
	) (any, error) {
		if f.String() != "json.Number" || (t != numericDateType && t != numericDatePtrType) {
			return data, nil
		}

		parsedFloat, err := strconv.ParseFloat(fmt.Sprint(data), 64)
		if err != nil {
			return nil, err
		}

		date := jwt.NewNumericDate(time.Unix(int64(parsedFloat), 0))

		if t == numericDateType {
			return *date, nil
		}

		return date, nil
	}
}
