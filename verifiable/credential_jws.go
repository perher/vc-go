/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vc-go/jwt"
)

// jwtTypeVC is the JWT type of VCDM 2.0 credentials (https://www.w3.org/TR/vc-jose-cose/#securing-with-jose).
const jwtTypeVC = "vc+jwt"

// MarshalJWS serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWS(
	signatureAlg JWSAlgorithm,
	signer jwt.ProofCreator,
	keyID string,
) (string, jose.Headers, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID, jcc.JWSHeaders())
}

// MarshalJWSString serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWSString(
	signatureAlg JWSAlgorithm,
	signer jwt.ProofCreator,
	keyID string,
) (string, error) {
	strJWT, _, err := marshalJWS(jcc, signatureAlg, signer, keyID, jcc.JWSHeaders())
	return strJWT, err
}

// JWSHeaders returns the JOSE headers that the JWS of the claims must have in addition to the signing headers.
// VCDM 2.0 credentials are typed "vc+jwt", other credentials need no additional headers.
func (jcc *JWTCredClaims) JWSHeaders() jose.Headers {
	if !HasBaseContext(jcc.VC, V2ContextURI) {
		return nil
	}

	return jose.Headers{jose.HeaderType: jwtTypeVC}
}
