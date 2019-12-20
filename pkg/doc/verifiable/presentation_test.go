/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

//nolint:lll
const validPresentation = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/1872",
      "type": [
        "VerifiableCredential",
        "AlumniCredential"
      ],
      "issuer": "https://example.edu/issuers/565049",
      "issuanceDate": "2010-01-01T19:03:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
          "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
          "name": [
            {
              "value": "Example University",
              "lang": "en"
            }
          ]
        }
      },
      "proof": {
        "type": "RsaSignature2018",
        "created": "2017-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.edu/issuers/keys/1",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
      }
    }
  ],
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-09-14T21:19:10Z",
    "proofPurpose": "authentication",
    "verificationMethod": "did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1",
    "challenge": "1f44d55f-f161-4938-a659-f8026467f126",
    "domain": "4jt78h47fh47",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78"
  },
  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

func TestNewPresentation(t *testing.T) {
	t.Run("creates a new Verifiable Presentation from JSON with valid structure", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)
		require.NotNil(t, vp)

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"}, vp.Context)

		// check id
		require.Equal(t, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", vp.ID)

		// check type
		require.Equal(t, []string{"VerifiablePresentation"}, vp.Type)

		// check verifiableCredentials
		require.NotNil(t, vp.Credentials())
		require.Len(t, vp.Credentials(), 1)

		// check holder
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vp.Holder)

		// check proof
		require.NotNil(t, vp.Proof)

		// check refreshService
		require.NotNil(t, vp.RefreshService)
		require.Equal(t, "https://example.edu/refresh/3732", vp.RefreshService.ID)
		require.Equal(t, "ManualRefreshService2018", vp.RefreshService.Type)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		vp, err := NewPresentation([]byte(emptyJSONDoc))
		require.Error(t, err)
		require.Nil(t, vp)
	})

	t.Run("fails to create a new Verifiable Presentation from non-JSON doc", func(t *testing.T) {
		vp, err := NewPresentation([]byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of verifiable presentation")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Context(t *testing.T) {
	t.Run("rejects verifiable presentation with empty context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation with invalid context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = []string{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://www.w3.org/2018/credentials/v1$'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_ID(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url ID", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.ID = "not valid presentation ID URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Type(t *testing.T) {
	t.Run("accepts verifiable presentation with single VerifiablePresentation type", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "VerifiablePresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.NoError(t, err)
	})

	t.Run("accepts verifiable presentation with multiple types where VerifiablePresentation is a first type",
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"VerifiablePresentation", "CredentialManagerPresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = NewPresentation(bytes)
			require.NoError(t, err)
		})

	t.Run("rejects verifiable presentation with no type defined", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation where single type is not VerifiablePresentation", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "CredentialManagerPresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation where several types are defined and first one is not VerifiablePresentation", //nolint:lll
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"CredentialManagerPresentation", "VerifiablePresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			vp, err := NewPresentation(bytes)
			require.Error(t, err)
			require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
			require.Nil(t, vp)
		})
}

func TestValidateVP_VerifiableCredential(t *testing.T) {
	t.Run("rejects verifiable presentation with not defined verifiableCredential", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Credential = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiableCredential is required")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Holder(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url holder", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Holder = "not valid presentation Holder URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "holder: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Proof(t *testing.T) {
	t.Run("rejects verifiable presentation with missed embedded proof", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded proof is missing")
		require.Nil(t, vp)
	})
}

func TestValidateVP_RefreshService(t *testing.T) {
	t.Run("accepts verifiable presentation with empty refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.NoError(t, err)
	})

	t.Run("test verifiable presentation with undefined id of refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &TypedID{Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: id is required")
		require.Nil(t, vp)
	})

	t.Run("test verifiable presentation with undefined type of refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &TypedID{ID: "https://example.edu/refresh/3732"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: type is required")
		require.Nil(t, vp)
	})

	t.Run("test verifiable presentation with invalid URL of id of credential schema", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &TypedID{ID: "invalid URL", Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := NewPresentation(bytes)

		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService.id: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestPresentation_MarshalJSON(t *testing.T) {
	vp, err := NewPresentation([]byte(validPresentation))
	require.NoError(t, err)
	require.NotEmpty(t, vp)

	// convert verifiable credential to json byte data
	vpData, err := vp.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vpData)

	// convert json byte data back to verifiable presentation
	vp2, err := NewPresentation(vpData)
	require.NoError(t, err)
	require.NotEmpty(t, vp2)

	// verify that verifiable presentations created by NewPresentation() and MarshalJSON() matches
	require.Equal(t, vp, vp2)
}

func TestPresentation_SetCredentials(t *testing.T) {
	r := require.New(t)
	vp := Presentation{}

	// Pass Credential struct
	vc := Credential{}
	err := vp.SetCredentials(vc)
	r.NoError(err)

	// Pass Credential struct pointer
	vcp := &Credential{}
	err = vp.SetCredentials(vcp)
	r.NoError(err)

	// Pass bytes (e.g. marshalled JSON)
	b := make([]byte, 3)
	err = vp.SetCredentials(b)
	r.NoError(err)

	// Pass string (e.g. JWS)
	s := "supposed to be JWS"
	err = vp.SetCredentials(s)
	r.NoError(err)

	// Invalid - pass another presentation.
	vpOther := &Presentation{}
	err = vp.SetCredentials(vpOther)
	r.Error(err)
	r.EqualError(err, "unsupported credential format")
}

func TestPresentation_decodeCredentials(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	jwtClaims, err := vc.JWTClaims(false)
	r.NoError(err)

	jws, err := jwtClaims.MarshalJWS(EdDSA, privKey, "k1")
	r.NoError(err)

	// single credential - JWS
	opts := defaultPresentationOpts()
	opts.publicKeyFetcher = SingleKey(pubKey)
	dCreds, err := decodeCredentials(jws, opts)
	r.NoError(err)
	r.Len(dCreds, 1)

	// single credential - JWS decoding failed (e.g. to no public key fetcher available)
	opts.publicKeyFetcher = nil
	_, err = decodeCredentials(jws, opts)
	r.Error(err)
}
