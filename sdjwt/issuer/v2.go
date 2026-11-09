/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/trustbloc/vc-go/sdjwt/common"
)

type builder interface {
	CreateDisclosuresAndDigests(
		path string,
		claims map[string]any,
		opts *newOpts,
	) ([]*DisclosureEntity, map[string]any, error)
	ExtractCredentialClaims(vcClaims map[string]any) (map[string]any, error)
	GenerateSalt() (string, error)
}

func getBuilderByVersion(
	version common.SDJWTVersion,
) builder {
	switch version {
	case common.SDJWTVersionV5:
		return NewSDJWTBuilderV5()
	default:
		return NewSDJWTBuilderV2()
	}
}

// SDJWTBuilderV2 represents builder struct for SD-JWT v2 spec.
type SDJWTBuilderV2 struct {
	defaultSaltSize int
}

// GenerateSalt generates salt.
func (s *SDJWTBuilderV2) GenerateSalt() (string, error) {
	return generateSalt(s.defaultSaltSize)
}

// NewSDJWTBuilderV2 returns new instance of SDJWTBuilderV2.
func NewSDJWTBuilderV2() *SDJWTBuilderV2 {
	return &SDJWTBuilderV2{
		defaultSaltSize: saltSizeBytes,
	}
}

// CreateDisclosuresAndDigests creates disclosures and digests.
func (s *SDJWTBuilderV2) CreateDisclosuresAndDigests(
	path string,
	claims map[string]any,
	opts *newOpts,
) ([]*DisclosureEntity, map[string]any, error) { // nolint:lll
	var disclosures []*DisclosureEntity

	var levelDisclosures []*DisclosureEntity

	digestsMap := make(map[string]any)

	decoyDisclosures, err := createDecoyDisclosures(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decoy disclosures: %w", err)
	}

	for key, value := range claims {
		curPath := key
		if path != "" {
			curPath = path + "." + key
		}

		if obj, ok := value.(map[string]any); ok && opts.structuredClaims {
			nestedDisclosures, nestedDigestsMap, e := s.CreateDisclosuresAndDigests(curPath, obj, opts)
			if e != nil {
				return nil, nil, e
			}

			digestsMap[key] = nestedDigestsMap

			disclosures = append(disclosures, nestedDisclosures...)
		} else {
			if _, ok := opts.nonSDClaimsMap[curPath]; ok {
				digestsMap[key] = value

				continue
			}

			disclosure, e := s.createDisclosure(key, value, opts)
			if e != nil {
				return nil, nil, fmt.Errorf("create disclosure: %w", e)
			}

			levelDisclosures = append(levelDisclosures, disclosure)
		}
	}

	disclosures = append(disclosures, levelDisclosures...)

	digests, err := createDigests(append(levelDisclosures, decoyDisclosures...), opts)
	if err != nil {
		return nil, nil, err
	}

	digestsMap[common.SDKey] = digests

	return disclosures, digestsMap, nil
}

func (s *SDJWTBuilderV2) createDisclosure(
	key string,
	value any,
	opts *newOpts,
) (*DisclosureEntity, error) {
	salt, err := opts.getSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	disclosure := []any{salt, key, value}

	disclosureBytes, err := opts.jsonMarshal(disclosure)
	if err != nil {
		return nil, fmt.Errorf("marshal disclosure: %w", err)
	}

	return &DisclosureEntity{
		Result: base64.RawURLEncoding.EncodeToString(disclosureBytes),
	}, nil
}

// ExtractCredentialClaims extracts credential claims.
func (s *SDJWTBuilderV2) ExtractCredentialClaims(vcClaims map[string]any) (map[string]any, error) {
	vc, ok := vcClaims[vcKey].(map[string]any)
	if !ok {
		return nil, errors.New("invalid vc claim")
	}

	return vc, nil
}
