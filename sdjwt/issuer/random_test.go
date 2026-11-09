/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomInt(t *testing.T) {
	const n = 4

	seen := map[int]bool{}

	for range 1000 {
		v, err := randomInt(n)
		require.NoError(t, err)
		require.GreaterOrEqual(t, v, 0)
		require.Less(t, v, n)

		seen[v] = true
	}

	require.Len(t, seen, n, "all values in [0, n) should be produced")
}

func TestShuffle(t *testing.T) {
	t.Run("keeps all elements", func(t *testing.T) {
		in := []string{"a", "b", "c", "d", "e"}

		s := slices.Clone(in)
		require.NoError(t, shuffle(s))

		slices.Sort(s)
		require.Equal(t, in, s)
	})

	t.Run("empty and single element", func(t *testing.T) {
		require.NoError(t, shuffle(nil))

		s := []string{"a"}
		require.NoError(t, shuffle(s))
		require.Equal(t, []string{"a"}, s)
	})

	t.Run("produces every permutation", func(t *testing.T) {
		seen := map[string]bool{}

		for range 1000 {
			s := []string{"a", "b", "c"}
			require.NoError(t, shuffle(s))

			seen[strings.Join(s, "")] = true
		}

		require.Len(t, seen, 6, "all 3! orderings should be produced")
	})
}
