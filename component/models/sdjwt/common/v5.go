/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

type commonV5 struct {
}

func newCommonV5() *commonV5 {
	return &commonV5{}
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func (c *commonV5) VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error {
	claims := utils.CopyMap(signedJWT.Payload)

	// check that the _sd_alg claim is present
	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	for _, disclosure := range disclosures {
		digest, err := GetHash(cryptoHash, disclosure)
		if err != nil {
			return err
		}

		found, err := isDigestInClaims(digest, claims)
		if err != nil {
			return err
		}

		if !found {
			parsed, err := getDisclosureClaim(disclosure)
			if err != nil {
				return err
			}

			if parsed.Type == DisclosureClaimTypeArrayElement {
				continue
			}

			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
}
