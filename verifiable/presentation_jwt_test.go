/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewJWTPresClaims(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
	require.NoError(t, err)

	audience := []string{"did:example:4a57546973436f6f6c4a4a57573"}

	t.Run("new JWT claims of VP with minimization", func(t *testing.T) {
		claims, err := newJWTPresClaims(vp, audience, true)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// issuer, ID and audience are filled in JWT claims
		require.Equal(t, vp.Holder, claims.Issuer)
		require.Equal(t, vp.ID, claims.ID)
		require.Equal(t, audience[0], claims.Audience[0])

		require.NotNil(t, claims.Presentation)

		// ID and Holder are cleared (minimized) in "vp" claim
		require.Empty(t, claims.Presentation[vpFldID])
		require.Empty(t, claims.Presentation[vpFldHolder])

		// minimization does not affect original VP
		require.NotEqual(t, vp.ID, claims.Presentation[vpFldID])
		require.NotEqual(t, vp.Holder, claims.Presentation[vpFldHolder])
	})

	t.Run("new JWT claims of VP without minimization", func(t *testing.T) {
		claims, err := newJWTPresClaims(vp, audience, false)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// issuer, ID and audience are filled in JWT claims
		require.Equal(t, vp.Holder, claims.Issuer)
		require.Equal(t, vp.ID, claims.ID)
		require.Equal(t, audience[0], claims.Audience[0])

		require.NotNil(t, claims.Presentation)

		// ID and Holder are cleared (minimized) in "vp" claim
		require.Equal(t, vp.ID, claims.Presentation[vpFldID])
		require.Equal(t, vp.Holder, claims.Presentation[vpFldHolder])
	})
}

func TestNewJWTPresClaims_Validity(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation), WithPresDisabledProofCheck())
	require.NoError(t, err)

	issuedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name       string
		opts       []JWTPresClaimsOpt
		wantIssued time.Time
		wantExpiry time.Time
	}{
		{
			name:       "issued now with default expiry",
			wantIssued: time.Now(),
			wantExpiry: time.Now().Add(DefaultPresentationJWTExpiry),
		},
		{
			name:       "issued at the given time",
			opts:       []JWTPresClaimsOpt{WithPresJWTIssuedAt(issuedAt)},
			wantIssued: issuedAt,
			wantExpiry: issuedAt.Add(DefaultPresentationJWTExpiry),
		},
		{
			name:       "expires after the given duration",
			opts:       []JWTPresClaimsOpt{WithPresJWTIssuedAt(issuedAt), WithPresJWTExpiry(time.Hour)},
			wantIssued: issuedAt,
			wantExpiry: issuedAt.Add(time.Hour),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := vp.JWTClaims(nil, false, tc.opts...)
			require.NoError(t, err)

			require.NotNil(t, claims.IssuedAt)
			require.NotNil(t, claims.Expiry)
			require.WithinDuration(t, tc.wantIssued, claims.IssuedAt.Time(), time.Second)
			require.WithinDuration(t, tc.wantExpiry, claims.Expiry.Time(), time.Second)
		})
	}
}
