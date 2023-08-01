/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// VerifySigningAlg ensures that a signing algorithm was used that was deemed secure for the application.
// The none algorithm MUST NOT be accepted.
func VerifySigningAlg(joseHeaders jose.Headers, secureAlgs []string) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return fmt.Errorf("missing alg")
	}

	if alg == afgjwt.AlgorithmNone {
		return fmt.Errorf("alg value cannot be 'none'")
	}

	if !contains(secureAlgs, alg) {
		return fmt.Errorf("alg '%s' is not in the allowed list", alg)
	}

	return nil
}

func contains(values []string, val string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}

	return false
}

// VerifyJWT checks that the JWT is valid using nbf, iat, and exp claims (if provided in the JWT).
func VerifyJWT(signedJWT *afgjwt.JSONWebToken, leeway time.Duration) error {
	var claims jwt.Claims

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &claims,
		TagName:          "json",
		Squash:           true,
		WeaklyTypedInput: true,
		DecodeHook:       utils.JSONNumberToJwtNumericDate(),
	})
	if err != nil {
		return fmt.Errorf("mapstruct verifyJWT. error: %w", err)
	}

	if err = d.Decode(signedJWT.Payload); err != nil {
		return fmt.Errorf("mapstruct verifyJWT decode. error: %w", err)
	}

	// Validate checks claims in a token against expected values.
	// It is validated using the expected.Time, or time.Now if not provided
	expected := jwt.Expected{}

	err = claims.ValidateWithLeeway(expected, leeway)
	if err != nil {
		return fmt.Errorf("invalid JWT time values: %w", err)
	}

	return nil
}

// VerifyTyp checks JWT header parameters for the SD-JWT component.
func VerifyTyp(joseHeaders jose.Headers, expectedTyp string) error {
	typ, ok := joseHeaders.Type()
	if !ok {
		return fmt.Errorf("missing typ")
	}

	if typ != expectedTyp {
		return fmt.Errorf("unexpected typ \"%s\"", typ)
	}

	return nil
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(
	disclosures []string,
	signedJWT *afgjwt.JSONWebToken,
) error {
	claims := utils.CopyMap(signedJWT.Payload)

	// check that the _sd_alg claim is present
	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	var disclosuresClaims []*DisclosureClaim

	for _, disclosure := range disclosures {
		digest, err := GetHash(cryptoHash, disclosure)
		if err != nil {
			return err
		}

		found, err := isDigestInClaims(digest, claims)
		if err != nil {
			return err
		}

		if found {
			continue
		}

		if disclosuresClaims == nil {
			disclosuresClaims, err = GetDisclosureClaims(disclosures)
			if err != nil {
				return fmt.Errorf("getDisclosureClaims: %w", err)
			}
		}

		// Check if given digest contains in nested disclosures
		if found = isDigestInDisclosures(disclosuresClaims, digest); found {
			continue
		}

		return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
	}

	return nil
}

func isDigestInDisclosures(disclosuresClaims []*DisclosureClaim, digest string) bool {
	for _, parsedDisclosure := range disclosuresClaims {
		if parsedDisclosure.Type != DisclosureClaimTypeObject {
			continue
		}
		found, err := isDigestInClaims(digest, parsedDisclosure.Value.(map[string]interface{}))
		if err != nil {
			return false
		}

		if found {
			return true
		}
	}

	return false
}
