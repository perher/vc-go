/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/veraison/go-cose"

	ed25519verifier "github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/proof/testsupport/commontest"
	"github.com/trustbloc/vc-go/vermethod"
)

func TestProofChecker_AllLD(t *testing.T) {
	t.Run("Test With all LD proofs", func(t *testing.T) {
		commontest.TestAllLDSignersVerifiers(t)
	})

	t.Run("Test With all jwt proofs", func(t *testing.T) {
		commontest.TestAllJWTSignersVerifiers(t)
	})

	t.Run("Test With all jwt proofs", func(t *testing.T) {
		commontest.TestEmbeddedProofChecker(t)
	})

	t.Run("Test With all cwt proofs", func(t *testing.T) {
		commontest.TestAllCWTSignersVerifiers(t)
	})
}

func TestProofChecker_CheckLDProof(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test", "issuerID"),
		checker.WithLDProofTypes(ed25519signature2018.New()))

	err := testable.CheckLDProof(&proof.Proof{}, "", nil, nil)
	require.ErrorContains(t, err, "roof missing public key id")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "invlaid",
	}, "", nil, nil)
	require.ErrorContains(t, err, "proof invalid public key id")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "lookupId",
	}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "unsupported proof type")

	err = testable.CheckLDProof(&proof.Proof{
		VerificationMethod: "lookupId",
		Type:               "Ed25519Signature2018",
	}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}

func TestProofChecker_CheckJWTProof(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test", "issuerID"),
		checker.WithJWTAlg(eddsa.New()))

	err := testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "talg"}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "missed kid in jwt header")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderKeyID: "tid"}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "missed alg in jwt header")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "tid", jose.HeaderAlgorithm: "talg"}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "invalid public key id")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "lookupId", jose.HeaderAlgorithm: "talg"}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "unsupported jwt alg")

	err = testable.CheckJWTProof(jose.Headers{
		jose.HeaderKeyID: "lookupId", jose.HeaderAlgorithm: "EdDSA"}, "issuerID", nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}

func TestProofChecker_CheckJWTProof_JWKAlgorithm(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	msg := []byte("msg")
	signature := ed25519.Sign(privKey, msg)

	tests := []struct {
		name    string
		jwkAlg  string
		wantErr string
	}{
		{name: "jwk without alg", jwkAlg: ""},
		{name: "jwk with matching alg", jwkAlg: "EdDSA"},
		{name: "jwk with other alg", jwkAlg: "ES256", wantErr: "jwt alg EdDSA does not match alg ES256 of the verification key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := jwksupport.JWKFromKey(pubKey)
			require.NoError(t, err)
			key.Algorithm = tc.jwkAlg
			headers := jose.Headers{jose.HeaderKeyID: "lookupId", jose.HeaderAlgorithm: "EdDSA"}

			checkers := map[string]interface {
				CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error
			}{
				"resolved": checker.New(
					testsupport.NewSingleJWKResolver("lookupId", key, "JsonWebKey2020", "issuerID"),
					checker.WithJWTAlg(eddsa.New()), checker.WithSignatureVerifiers(ed25519verifier.New())),
				"embedded": checker.NewEmbeddedJWKProofChecker(key,
					checker.WithJWTAlg(eddsa.New()), checker.WithSignatureVerifiers(ed25519verifier.New())),
			}
			for name, c := range checkers {
				err = c.CheckJWTProof(headers, "issuerID", msg, signature)
				if tc.wantErr != "" {
					require.ErrorContains(t, err, tc.wantErr, name)
				} else {
					require.NoError(t, err, name)
				}
			}
		})
	}
}

func TestProofCheckerIssuer(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test", "awesome"),
		checker.WithJWTAlg(eddsa.New()))

	err := testable.CheckJWTProof(jose.Headers{jose.HeaderKeyID: "tid", jose.HeaderAlgorithm: "EdDSA"},
		"abcd",
		nil, nil)
	require.ErrorContains(t, err, `invalid public key id: invalid issuer. expected "awesome" got "abcd"`)
}

func TestProofChecker_CheckCWTProof(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test", "issuerID"),
		checker.WithCWTAlg(eddsa.New()))

	t.Run("missed kid and COSE_Key in cwt header", func(t *testing.T) {
		err := testable.CheckCWTProof(checker.CheckCWTProofRequest{
			Algo: cose.AlgorithmEd25519,
		}, "issuerID", nil, nil)
		require.ErrorContains(t, err, "missed kid and COSE_Key in cwt header")
	})

	t.Run("missed alg in cwt header", func(t *testing.T) {
		err := testable.CheckCWTProof(checker.CheckCWTProofRequest{
			KeyID: "tid",
		}, "issuerID", nil, nil)
		require.ErrorContains(t, err, "missed alg in cwt header")
	})

	t.Run("invalid public key id", func(t *testing.T) {
		err := testable.CheckCWTProof(checker.CheckCWTProofRequest{
			KeyID: "tid",
			Algo:  1,
		}, "issuerID", nil, nil)
		require.ErrorContains(t, err, "invalid public key id")
	})

	t.Run("unsupported cwt alg:", func(t *testing.T) {
		err := testable.CheckCWTProof(checker.CheckCWTProofRequest{
			KeyID: "lookupId",
			Algo:  1,
		}, "issuerID", nil, nil)
		require.ErrorContains(t, err, "unsupported cwt alg:")
	})

	t.Run("unsupported cwt alg:", func(t *testing.T) {
		err := testable.CheckCWTProof(checker.CheckCWTProofRequest{
			KeyID: "lookupId",
			Algo:  cose.AlgorithmEd25519,
		}, "issuerID", nil, nil)
		require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
	})
}

func TestProofCheckerIssuerCwt(t *testing.T) {
	testable := checker.New(
		testsupport.NewSingleKeyResolver("lookupId", []byte{}, "test", "awesome"),
		checker.WithCWTAlg(eddsa.New()))

	err := testable.CheckCWTProof(
		checker.CheckCWTProofRequest{
			KeyID: "tid",
			Algo:  cose.AlgorithmEd25519,
		},
		"abcd", nil, nil)

	require.ErrorContains(t, err, `invalid public key id: invalid issuer. expected "awesome" got "abcd"`)
}

func TestEmbeddedVMProofChecker_CheckJWTProof(t *testing.T) {
	testable := checker.NewEmbeddedVMProofChecker(
		&vermethod.VerificationMethod{Type: "test"},
		checker.WithJWTAlg(eddsa.New()))

	err := testable.CheckJWTProof(jose.Headers{}, "", nil, nil)
	require.ErrorContains(t, err, "missed alg in jwt header")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "talg"}, "", nil, nil)
	require.ErrorContains(t, err, "unsupported jwt alg")

	err = testable.CheckJWTProof(jose.Headers{jose.HeaderAlgorithm: "EdDSA"}, "", nil, nil)
	require.ErrorContains(t, err, "can't verifiy with \"test\" verification method")
}

func TestFindIssuerInPayload(t *testing.T) {
	c := checker.ProofChecker{}

	t.Run("$.vc.issuer.id", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"iss": "123", "issuer": "abcd", "vc":{"issuer":{"id":"did:example:123"}}}`))
		require.Equal(t, "did:example:123", result)
	})

	t.Run("$.vc.issuer", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"iss": "123", "issuer": "abcd", "vc":{"issuer":"did:example:123"}}`))
		require.Equal(t, "did:example:123", result)
	})

	t.Run("$.issuer.id", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"iss": "123", "issuer": {"id" : "abcd"}}`))
		require.Equal(t, "abcd", result)
	})

	t.Run("$.issuer", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"iss": "123", "issuer": "abcd"}`))
		require.Equal(t, "abcd", result)
	})

	t.Run("$.iss", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"iss": "123"}`))
		require.Equal(t, "123", result)
	})

	t.Run("none", func(t *testing.T) {
		result := c.FindIssuer([]byte(`{"a": "123"}`))
		require.Equal(t, "", result)
	})
}
