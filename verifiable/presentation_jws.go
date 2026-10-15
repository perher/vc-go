/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// jwtTypeVP is the JWT type of VCDM 2.0 presentations (https://www.w3.org/TR/vc-jose-cose/#securing-with-jose).
const jwtTypeVP = "vp+jwt"

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func (jpc *JWTPresClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer jwt.ProofCreator, keyID string) (string, error) {
	strJWT, _, err := marshalJWS(jpc, signatureAlg, signer, keyID, jpc.JWSHeaders())
	return strJWT, err
}

// JWSHeaders returns the JOSE headers that the JWS of the claims must have in addition to the signing headers.
// VCDM 2.0 presentations are typed "vp+jwt", other presentations need no additional headers.
func (jpc *JWTPresClaims) JWSHeaders() jose.Headers {
	if !jpc.InlineVPClaims {
		return nil
	}

	return jose.Headers{jose.HeaderType: jwtTypeVP}
}

func unmarshalPresJWSClaims(vpJWT string, verifier jwt.ProofChecker, expectedProofIssuer *string) (*JWTPresClaims, error) {
	var claims JWTPresClaims

	_, err := unmarshalJWT(vpJWT, &claims)
	if err != nil {
		return nil, err
	}

	if verifier != nil {
		err = jwt.CheckProof(vpJWT, verifier, expectedProofIssuer, nil)
		if err != nil {
			return nil, fmt.Errorf("jwt proof check: %w", err)
		}
	}

	return &claims, err
}

func decodeVPFromJWS(vpJWT string, verifier jwt.ProofChecker, expectedProofIssuer *string) ([]byte, rawPresentation, error) {
	return decodePresJWT(vpJWT, func(vpJWT string) (*JWTPresClaims, error) {
		return unmarshalPresJWSClaims(vpJWT, verifier, expectedProofIssuer)
	})
}
