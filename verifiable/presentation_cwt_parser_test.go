/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func newTestCWTPresentation(t *testing.T, claims map[string]any) []byte {
	t.Helper()

	payload, err := cbor.Marshal(claims)
	require.NoError(t, err)

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			},
		},
		Payload:   payload,
		Signature: []byte("signature"),
	}

	data, err := cbor.Marshal(msg)
	require.NoError(t, err)

	return data
}

func TestPresentationCWTParserVPClaim(t *testing.T) {
	parser := &PresentationCWTParser{}

	t.Run("vp claim present", func(t *testing.T) {
		data := newTestCWTPresentation(t, map[string]any{
			"iss": "did:example:holder",
			"vp": map[string]any{
				"type": "VerifiablePresentation",
			},
		})

		res, err := parser.parse(data, &presentationOpts{})
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "VerifiablePresentation", res.VPRaw["type"])
	})

	for name, claims := range map[string]map[string]any{
		"vp claim missing":          {"iss": "did:example:holder"},
		"vp claim is not an object": {"vp": "not an object"},
	} {
		t.Run(name, func(t *testing.T) {
			data := newTestCWTPresentation(t, claims)

			// The parser itself accepts the CWT and leaves the presentation body empty...
			res, err := parser.parse(data, &presentationOpts{})
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Nil(t, res.VPRaw)
			require.NotNil(t, res.VPCwt)

			// ...and ParsePresentation rejects it during validation.
			for _, opts := range [][]PresentationOpt{
				nil,
				{WithPresDisabledProofCheck(), WithDisabledJSONLDChecks()},
			} {
				vp, err := ParsePresentation(data, opts...)
				require.ErrorContains(t, err, "@context is required")
				require.Nil(t, vp)
			}
		})
	}
}
