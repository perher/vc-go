/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vc-go/jwt"
)

const (
	issuerID = "did:example:76e12ec712ebc6f1c221ebfeb1f"
)

func TestDecodeJWT(t *testing.T) {
	joseHeaders, vcBytes, err := decodeCredJWT("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse JWT: JWT of compacted JWS form is supported only")
	require.Nil(t, vcBytes)
	require.Nil(t, joseHeaders)
}

func TestRefineVcFromJwtClaims(t *testing.T) {
	issued := time.Date(2019, time.August, 10, 0, 0, 0, 0, time.UTC)
	vcID := "http://example.edu/credentials/3732"
	expired := time.Date(2029, time.August, 10, 0, 0, 0, 0, time.UTC)

	credClaims := &jwt.Claims{
		Issuer:    issuerID,
		NotBefore: josejwt.NewNumericDate(issued),
		ID:        vcID,
		IssuedAt:  josejwt.NewNumericDate(issued),
		Expiry:    josejwt.NewNumericDate(expired),
	}

	t.Run("Credentials V1", func(t *testing.T) {
		vcMap := map[string]interface{}{
			"issuer": "unknown",
		}
		jwtCredClaims := &JWTCredClaims{
			Claims: credClaims,
			VC:     vcMap,
		}

		require.NoError(t, jwtCredClaims.refineFromJWTClaims())
		require.Equal(t, issuerID, vcMap["issuer"])
		require.Equal(t, "2019-08-10T00:00:00Z", vcMap["issuanceDate"])
		require.Equal(t, "2029-08-10T00:00:00Z", vcMap["expirationDate"])
	})

	t.Run("Credentials V2", func(t *testing.T) {
		vcMap := map[string]interface{}{
			"@context": []string{V2ContextURI},
			"issuer":   "unknown",
		}
		jwtCredClaims := &JWTCredClaims{
			Claims: credClaims,
			VC:     vcMap,
		}

		require.NoError(t, jwtCredClaims.refineFromJWTClaims())
		require.Equal(t, issuerID, vcMap["issuer"])
		require.Equal(t, vcID, vcMap["id"])
		require.Equal(t, "2019-08-10T00:00:00Z", vcMap["validFrom"])
		require.Equal(t, "2029-08-10T00:00:00Z", vcMap["validUntil"])
	})

	t.Run("Credentials V2 issuer DID must match iss", func(t *testing.T) {
		jwtCredClaims := &JWTCredClaims{
			Claims: credClaims,
			VC: map[string]interface{}{
				"@context": []string{V2ContextURI},
				"issuer":   "did:example:other",
			},
		}

		require.ErrorContains(t, jwtCredClaims.refineFromJWTClaims(), "missmatch")
	})

	t.Run("without JWT claims", func(t *testing.T) {
		vcMap := map[string]interface{}{
			"@context": []string{V2ContextURI},
			"issuer":   issuerID,
		}
		jwtCredClaims := &JWTCredClaims{VC: vcMap}

		require.NoError(t, jwtCredClaims.refineFromJWTClaims())
		want := map[string]interface{}{
			"@context": []string{V2ContextURI},
			"issuer":   issuerID,
		}
		require.Equal(t, want, vcMap)
	})

	t.Run("without credential", func(t *testing.T) {
		jwtCredClaims := &JWTCredClaims{Claims: credClaims}

		require.ErrorContains(t, jwtCredClaims.refineFromJWTClaims(), "missing credential")
	})
}

func TestJWTCredClaims_MarshalJSON(t *testing.T) {
	claims := &jwt.Claims{
		Issuer:   issuerID,
		ID:       "urn:uuid:7f1d3c2e-0d1c-4b5e-9a57-0f6a1d2c3b4a",
		IssuedAt: josejwt.NewNumericDate(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)),
	}
	vcV1 := map[string]interface{}{
		"@context":          []interface{}{V1ContextURI},
		"type":              []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{"id": "did:example:holder"},
	}
	vcV2 := map[string]interface{}{
		"@context":          []interface{}{V2ContextURI},
		"type":              []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{"id": "did:example:holder"},
	}

	tests := []struct {
		name string
		vc   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "Credentials V1 are nested in the vc claim",
			vc:   vcV1,
			want: map[string]interface{}{
				"iss": issuerID,
				"jti": "urn:uuid:7f1d3c2e-0d1c-4b5e-9a57-0f6a1d2c3b4a",
				"iat": float64(1767323045),
				"vc":  vcV1,
			},
		},
		{
			name: "Credentials V2 are the JWT claims set",
			vc:   vcV2,
			want: map[string]interface{}{
				"iss":               issuerID,
				"jti":               "urn:uuid:7f1d3c2e-0d1c-4b5e-9a57-0f6a1d2c3b4a",
				"iat":               float64(1767323045),
				"@context":          []interface{}{V2ContextURI},
				"type":              []interface{}{"VerifiableCredential"},
				"credentialSubject": map[string]interface{}{"id": "did:example:holder"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(&JWTCredClaims{Claims: claims, VC: tc.vc})
			require.NoError(t, err)

			var got map[string]interface{}
			err = json.Unmarshal(b, &got)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestJWTCredClaims_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantClaims *jwt.Claims
		wantVC     map[string]interface{}
	}{
		{
			name:       "vc claim",
			data:       `{"iss":"did:example:issuer","vc":{"@context":["` + V1ContextURI + `"],"issuer":"did:example:issuer"}}`,
			wantClaims: &jwt.Claims{Issuer: "did:example:issuer"},
			wantVC:     map[string]interface{}{"@context": []interface{}{V1ContextURI}, "issuer": "did:example:issuer"},
		},
		{
			name:       "claims set with JWT claims",
			data:       `{"iss":"did:example:issuer","@context":["` + V2ContextURI + `"],"issuer":"did:example:issuer"}`,
			wantClaims: &jwt.Claims{Issuer: "did:example:issuer"},
			wantVC:     map[string]interface{}{"@context": []interface{}{V2ContextURI}, "issuer": "did:example:issuer"},
		},
		{
			name:       "claims set without JWT claims",
			data:       `{"@context":["` + V2ContextURI + `"],"issuer":"did:example:issuer"}`,
			wantClaims: &jwt.Claims{},
			wantVC:     map[string]interface{}{"@context": []interface{}{V2ContextURI}, "issuer": "did:example:issuer"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got JWTCredClaims
			err := json.Unmarshal([]byte(tc.data), &got)
			require.NoError(t, err)
			require.Equal(t, tc.wantClaims, got.Claims)
			require.Equal(t, tc.wantVC, got.VC)
		})
	}
}

func TestJWTCredClaims_ToSDJWTCredentialPayload(t *testing.T) {
	jcc := &JWTCredClaims{
		Claims: &jwt.Claims{
			Issuer:    "issuer",
			Subject:   "subject",
			Audience:  josejwt.Audience{"leela", "fry"},
			NotBefore: josejwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
			ID:        "http://example.edu/credentials/3732",
		},
		VC: map[string]interface{}{
			"@context": []interface{}{
				"https://www.w3.org/2018/credentials/v1",
				"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
			},
			"id":   "http://example.edu/credentials/1989",
			"type": "VerifiableCredential",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:iuajk1f712ebc6f1c276e12ec21",
			},
			"issuer": map[string]interface{}{
				"id":   "did:example:09s12ec712ebc6f1c671ebfeb1f",
				"name": "Example University",
			},
			"issuanceDate": "2020-01-01T10:54:01Z",
			"credentialStatus": map[string]interface{}{
				"id":   "https://example.gov/status/65",
				"type": "CredentialStatusList2017",
			},
		},
	}

	got, err := jcc.ToSDJWTV5CredentialPayload()
	require.NoError(t, err)
	require.NotContains(t, string(got), `"vc"`)

	var jccMapped *JWTCredClaims
	err = json.Unmarshal(got, &jccMapped)
	require.NoError(t, err)

	require.Equal(t, jcc, jccMapped)
}
