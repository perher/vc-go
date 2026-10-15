/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
	afgotime "github.com/trustbloc/did-go/doc/util/time"

	"github.com/trustbloc/vc-go/proof/testsupport"

	"github.com/trustbloc/kms-go/spi/kms"
)

func TestV1JWTCredClaimsMarshalJWS(t *testing.T) {
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")

	vc, err := parseTestCredential(t, []byte(v1ValidCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWSString(RS256, proofCreator, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")
		require.NoError(t, err)

		jwtVC, err := ParseCredential([]byte(jws), WithProofChecker(proofChecker))

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})
}

func TestV2JWTCredClaimsMarshalJWS(t *testing.T) {
	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")

	vc, err := parseTestCredential(t, []byte(v2ValidCredential), WithDisabledProofCheck())
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWSString(RS256, proofCreator, "did:example:76e12ec712ebc6f1c221ebfeb1f#key1")
		require.NoError(t, err)

		jwtVC, err := ParseCredential([]byte(jws), WithProofChecker(proofChecker))

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})
}

func TestCreateSignedJWTVC(t *testing.T) {
	const pubKeyID = "did:example:76e12ec712ebc6f1c221ebfeb1f#key1"

	proofCreator, proofChecker := testsupport.NewKMSSigVerPair(t, kms.RSARS256Type, pubKeyID)

	tests := []struct {
		name        string
		context     string
		minimize    bool
		wantVCClaim bool
	}{
		{name: "Credentials V1", context: V1ContextURI, wantVCClaim: true},
		{name: "Credentials V1 minimized", context: V1ContextURI, minimize: true, wantVCClaim: true},
		{name: "Credentials V2", context: V2ContextURI},
		{name: "Credentials V2 are never minimized", context: V2ContextURI, minimize: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issued := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
			vc, err := CreateCredential(CredentialContents{
				Context: []string{tc.context},
				ID:      "urn:uuid:7f1d3c2e-0d1c-4b5e-9a57-0f6a1d2c3b4a",
				Types:   []string{VCType},
				Issuer:  &Issuer{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"},
				Issued:  afgotime.NewTime(issued),
				Expired: afgotime.NewTime(issued.Add(time.Hour)),
				Subject: []Subject{{ID: "did:example:ebfeb1f712ebc6f1c276e12ec21"}},
			}, nil)
			require.NoError(t, err)

			jwtVC, err := vc.CreateSignedJWTVC(tc.minimize, RS256, proofCreator, pubKeyID)
			require.NoError(t, err)

			payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(jwtVC.JWTEnvelope.JWT, ".")[1])
			require.NoError(t, err)

			var payload map[string]interface{}
			err = json.Unmarshal(payloadBytes, &payload)
			require.NoError(t, err)
			require.Equal(t, tc.wantVCClaim, payload["vc"] != nil)

			if !tc.wantVCClaim {
				var credential map[string]interface{}
				err = json.Unmarshal([]byte(vc.stringJSON(t)), &credential)
				require.NoError(t, err)

				for field, value := range credential {
					require.Equal(t, value, payload[field], field)
				}
			}

			parsed, err := parseTestCredential(t, []byte(jwtVC.JWTEnvelope.JWT), WithProofChecker(proofChecker))
			require.NoError(t, err)
			require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, parsed.ToRawJSON()))
		})
	}
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestV1CredJWSDecoderUnmarshal(t *testing.T) {
	verificationKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key1"
	otherVerificationKeyID := "did:example:76e12ec712ebc6f1c221ebfeb1f#key2"

	proofCreators, proofChecker := testsupport.NewKMSSignersAndVerifier(t, []*testsupport.SigningKey{
		{Type: kms.RSARS256, PublicKeyID: verificationKeyID},
		{Type: kms.RSARS256, PublicKeyID: otherVerificationKeyID},
	})

	validJWS := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], verificationKeyID, false)
	jwsWithWrongKey := createRS256JWS(t, []byte(jwtTestCredential), proofCreators[0], otherVerificationKeyID, false)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		jwtVC, err := ParseCredential(validJWS, WithProofChecker(proofChecker))
		require.NoError(t, err)

		vc, err := parseTestCredential(t, []byte(jwtTestCredential), WithDisabledProofCheck())
		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), jsonObjectToString(t, jwtVC.ToRawJSON()))
	})

	t.Run("JWS with 'iss' and issuer.id miss match", func(t *testing.T) {
		original := strings.Split(string(validJWS), ".")

		var claims map[string]interface{}
		claimsBytes, err := base64.RawURLEncoding.DecodeString(original[1])
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(claimsBytes, &claims))

		claims["iss"] = "did:example:other_issuer"

		claimsBytes, err = json.Marshal(claims)
		require.NoError(t, err)

		jwsWithMissMatch := original[0] + "." + base64.RawURLEncoding.EncodeToString(claimsBytes) + "." + original[2]

		_, err = ParseCredential([]byte(jwsWithMissMatch), WithProofChecker(proofChecker))
		require.ErrorContains(t, err, "iss(did:example:other_issuer) claim and "+
			"vc.issuer.id(did:example:76e12ec712ebc6f1c221ebfeb1f) missmatch")
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		_, err := ParseCredential([]byte(`"invalid JWS"`), WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported credential format")
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		jwtCompact, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		_, err = ParseCredential([]byte(jwtCompact), WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode new JWT credential")
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		_, err := ParseCredential(jwsWithWrongKey, WithProofChecker(proofChecker))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWS proof check")
	})
}
