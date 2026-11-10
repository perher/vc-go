/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/multiformats/go-multibase"
)

// nolint:gochecknoglobals
var DefaultRelatedResourceValidator = NewRelatedResourceValidator()

const (
	defaultCacheSize = 100
	defaultCacheTTL  = time.Minute

	// sriParts is the number of parts in a digestSRI value: "<hash algorithm>-<digest>".
	sriParts = 2

	// A multihash SHA2-256 digest starts with a 2-byte header: the function code and the digest length.
	multihashSHA256Code = 0x12
	multihashHeaderLen  = 2
)

type RelatedResourceValidator struct {
	cfg *RelatedResourceValidatorOptions
}

type CachedResource struct {
	Sha384Hash []byte
	Sha256Hash []byte
	Sha512Hash []byte
}

type RelatedResourceValidatorOptions struct {
	HTTPClient httpClient
	Cache      *expirable.LRU[string, *CachedResource]
}

func WithHTTPClient(client httpClient) func(*RelatedResourceValidatorOptions) {
	return func(o *RelatedResourceValidatorOptions) {
		o.HTTPClient = client
	}
}

func WithCache(cache *expirable.LRU[string, *CachedResource]) func(*RelatedResourceValidatorOptions) {
	return func(o *RelatedResourceValidatorOptions) {
		o.Cache = cache
	}
}

func NewRelatedResourceValidator(
	opts ...func(*RelatedResourceValidatorOptions),
) *RelatedResourceValidator {
	option := &RelatedResourceValidatorOptions{
		HTTPClient: http.DefaultClient,
		Cache:      expirable.NewLRU[string, *CachedResource](defaultCacheSize, nil, defaultCacheTTL),
	}
	for _, o := range opts {
		o(option)
	}

	return &RelatedResourceValidator{
		cfg: option,
	}
}

func (r *RelatedResourceValidator) Fetch(targetURL string) (*CachedResource, error) {
	if v, ok := r.cfg.Cache.Get(targetURL); ok {
		return v, nil
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil) //nolint:noctx // the public API takes no context.Context yet
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("create related resource request: %s", targetURL))
	}

	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("fetch related resource: %s", targetURL))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Join(fmt.Errorf("related resource fetch failed with status code: %d",
			resp.StatusCode))
	}

	if resp.Body == nil {
		return nil, fmt.Errorf("empty related resource: %s", targetURL)
	}

	var data []byte

	defer func() {
		_ = resp.Body.Close() // nolint:errcheck
	}()

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("read related resource: %s", targetURL))
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty related resource: %s", targetURL)
	}

	cachedResource := r.calculateHashes(data)
	r.cfg.Cache.Add(targetURL, cachedResource)

	return cachedResource, nil
}

func (r *RelatedResourceValidator) Validate(
	credentials []*Credential,
) error {
	channels := make([]chan error, 0)

	for _, cred := range credentials {
		for _, res := range cred.Contents().RelatedResources {
			ch := make(chan error)
			channels = append(channels, ch)
			currentResource := res

			go func() {
				defer close(ch)

				resourceData, err := r.Fetch(currentResource.Id)
				if err != nil {
					ch <- errors.Join(err, fmt.Errorf("fetch related resource: %s", currentResource.Id))
					return
				}

				if err = r.validateSingleResource(&currentResource, resourceData); err != nil {
					ch <- errors.Join(err, fmt.Errorf("validate related resource hash: %s", currentResource.Id))
					return
				}
			}()
		}
	}

	var finalErr error

	for _, ch := range channels {
		finalErr = errors.Join(finalErr, <-ch)
	}

	return finalErr
}

func (r *RelatedResourceValidator) validateSingleResource(
	res *RelatedResource,
	cachedResource *CachedResource,
) error {
	var hashAlgo string

	var hash string

	if res.DigestSRI != "" {
		sp := strings.Split(res.DigestSRI, "-")

		if len(sp) != sriParts {
			return fmt.Errorf("invalid digest SRI format: %s", res.DigestSRI)
		}

		hashAlgo = sp[0]
		hash = sp[1]
	} else if res.DigestMultiBase != "" {
		hashAlgo = "sha256"
		hash = res.DigestMultiBase
	}

	return r.validateHash(hash, hashAlgo, res, cachedResource)
}

func (r *RelatedResourceValidator) validateHash(
	hash string,
	hashAlgo string,
	res *RelatedResource,
	cachedResource *CachedResource,
) error {
	enc, decodedDigest, err := multibase.Decode(hash)
	if err != nil {
		return errors.Join(err, fmt.Errorf("decode digest: %s", hash))
	}

	var rawHash []byte

	switch strings.ToLower(hashAlgo) {
	case "sha256":
		rawHash = cachedResource.Sha256Hash
	case "sha384":
		rawHash = cachedResource.Sha384Hash
	case "sha512":
		rawHash = cachedResource.Sha512Hash
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", hashAlgo)
	}

	hasHeader := enc == multibase.Base64url && len(decodedDigest) >= multihashHeaderLen &&
		decodedDigest[0] == multihashSHA256Code && decodedDigest[1] == sha256.Size
	if hasHeader { // skip header
		decodedDigest = decodedDigest[multihashHeaderLen:]
	}

	if !bytes.Equal(rawHash, decodedDigest) {
		return fmt.Errorf("hash mismatch: %s", res.Id)
	}

	return nil
}

func (r *RelatedResourceValidator) calculateHashes(data []byte) *CachedResource {
	sha384Hash := sha512.Sum384(data)
	sha256Hash := sha256.Sum256(data)
	sha512Hash := sha512.Sum512(data)

	return &CachedResource{
		Sha384Hash: sha384Hash[:],
		Sha256Hash: sha256Hash[:],
		Sha512Hash: sha512Hash[:],
	}
}
