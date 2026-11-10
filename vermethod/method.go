/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vermethod

import "github.com/trustbloc/kms-go/doc/jose/jwk"

// VerificationMethod is defined either as raw public key bytes (Value field) or as JSON Web Key.
type VerificationMethod struct {
	Type  string
	Value []byte
	JWK   *jwk.JWK
}
