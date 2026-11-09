/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presexch

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckPathValuePathPrefix(t *testing.T) {
	const prefixErr = "expected $ or @ at start of path"

	credential := map[string]any{"name": "Alice"}

	t.Run("path starting with $ is accepted", func(t *testing.T) {
		require.NoError(t, checkPathValue(false, "$.name", credential, &Field{}, nil))
	})

	t.Run("path without $ or @ prefix is rejected", func(t *testing.T) {
		err := checkPathValue(false, "name", credential, &Field{}, nil)
		require.ErrorContains(t, err, prefixErr)
	})

	t.Run("empty path is rejected", func(t *testing.T) {
		err := checkPathValue(false, "", credential, &Field{}, nil)
		require.ErrorContains(t, err, prefixErr)
	})

	t.Run("path starting with @ passes the prefix check", func(t *testing.T) {
		err := checkPathValue(false, "@.name", credential, &Field{}, nil)
		if err != nil {
			require.NotContains(t, err.Error(), prefixErr)
		}
	})
}
