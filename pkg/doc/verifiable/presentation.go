/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

const basePresentationSchema = `
{
  "required": [
    "@context",
    "type",
    "verifiableCredential"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^https://www.w3.org/2018/credentials/v1$"
        }
      ],
      "uniqueItems": true,
      "additionalItems": {
        "oneOf": [
          {
            "type": "object"
          },
          {
            "type": "string"
          }
        ]
      }
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "pattern": "^VerifiablePresentation$"
            }
          ],
          "minItems": 1
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ],
      "additionalItems": {
        "type": "string"
      }
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        }
      ]
    },
    "holder": {
      "type": "string",
      "format": "uri"
    },
    "proof": {
      "anyOf": [
        {
          "type": "array",
          "items": [
            {
              "$ref": "#/definitions/proof"
            }
          ]
        },
        {
          "$ref": "#/definitions/proof"
        }
      ]
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        }
      }
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

//nolint:gochecknoglobals
var basePresentationSchemaLoader = gojsonschema.NewStringLoader(basePresentationSchema)

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.NewCredential().
type MarshalledCredential []byte

// Presentation Verifiable Presentation base data model definition
type Presentation struct {
	Context        []string
	CustomContext  []interface{}
	ID             string
	Type           []string
	credentials    []interface{}
	Holder         string
	Proof          Proof
	RefreshService *TypedID
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	byteCred, err := json.Marshal(vp.raw())
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}

// JWTClaims converts Verifiable Presentation into JWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) JWTClaims(audience []string, minimizeVP bool) *JWTPresClaims {
	return newJWTPresClaims(vp, audience, minimizeVP)
}

// Credentials returns current credentials of presentation.
func (vp *Presentation) Credentials() []interface{} {
	return vp.credentials
}

// SetCredentials defines credentials of presentation.
// The credential could be string/byte (probably serialized JWT) or Credential structure.
func (vp *Presentation) SetCredentials(creds ...interface{}) error {
	for i := range creds {
		switch creds[i].(type) {
		case []byte, string, *Credential, Credential:
			// Acceptable.
		default:
			return errors.New("unsupported credential format")
		}
	}

	vp.credentials = creds

	return nil
}

// MarshalledCredentials provides marshalled credentials enclosed into Presentation in raw byte array format.
// They can be used to decode Credentials into struct.
func (vp *Presentation) MarshalledCredentials() ([]MarshalledCredential, error) {
	mCreds := make([]MarshalledCredential, len(vp.credentials))

	for i := range vp.credentials {
		cred := vp.credentials[i]
		switch c := cred.(type) {
		case string:
			mCreds[i] = MarshalledCredential(c)
		case []byte:
			mCreds[i] = c
		default:
			credBytes, err := json.Marshal(cred)
			if err != nil {
				return nil, fmt.Errorf("marshal credentials from presentation: %w", err)
			}

			mCreds[i] = credBytes
		}
	}

	return mCreds, nil
}

func (vp *Presentation) raw() *rawPresentation {
	return &rawPresentation{
		Context:        vp.Context,
		ID:             vp.ID,
		Type:           vp.Type,
		Credential:     vp.credentials,
		Holder:         vp.Holder,
		Proof:          vp.Proof,
		RefreshService: vp.RefreshService,
	}
}

// rawPresentation is a basic verifiable credential
type rawPresentation struct {
	Context        interface{} `json:"@context,omitempty"`
	ID             string      `json:"id,omitempty"`
	Type           interface{} `json:"type,omitempty"`
	Credential     interface{} `json:"verifiableCredential,omitempty"`
	Holder         string      `json:"holder,omitempty"`
	Proof          Proof       `json:"proof,omitempty"`
	RefreshService *TypedID    `json:"refreshService,omitempty"`
}

// presentationOpts holds options for the Verifiable Presentation decoding
type presentationOpts struct {
	publicKeyFetcher   PublicKeyFetcher
	disabledProofCheck bool
}

// PresentationOpt is the Verifiable Presentation decoding option
type PresentationOpt func(opts *presentationOpts)

// WithPresPublicKeyFetcher indicates that Verifiable Presentation should be decoded from JWS using
// the public key fetcher.
func WithPresPublicKeyFetcher(fetcher PublicKeyFetcher) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.publicKeyFetcher = fetcher
	}
}

// NewPresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func NewPresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	// Apply options
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	vpDataDecoded, vpRaw, err := decodeRawPresentation(vpData, vpOpts)
	if err != nil {
		return nil, err
	}

	err = validatePresentation(vpDataDecoded)
	if err != nil {
		return nil, err
	}

	types, err := decodeType(vpRaw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill presentation types from raw: %w", err)
	}

	context, customContext, err := decodeContext(vpRaw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill presentation contexts from raw: %w", err)
	}

	creds, err := decodeCredentials(vpRaw.Credential, vpOpts)
	if err != nil {
		return nil, fmt.Errorf("decode credentials of presentation: %w", err)
	}

	vp := &Presentation{
		Context:        context,
		CustomContext:  customContext,
		ID:             vpRaw.ID,
		Type:           types,
		credentials:    creds,
		Holder:         vpRaw.Holder,
		Proof:          vpRaw.Proof,
		RefreshService: vpRaw.RefreshService,
	}

	return vp, nil
}

// decodeCredentials decodes credential(s) embedded into presentation.
// It must be one of the following:
// 1) string - it could be credential decoded into e.g. JWS.
// 2) the same as 1) but as array - e.g. zero ore more JWS
// 3) struct (should be map[string]interface{}) representing credential data model
// 4) the same as 3) but as array - i.e. zero or more credentials structs.
func decodeCredentials(rawCred interface{}, opts *presentationOpts) ([]interface{}, error) {
	marshalSingleCredFn := func(cred interface{}) (interface{}, error) {
		// Check the case when VC is defined in string format (e.g. JWT).
		// Decode credential and keep result of decoding.
		if sCred, ok := cred.(string); ok {
			bCred := []byte(sCred)

			credDecoded, err := decodeRaw(bCred, !opts.disabledProofCheck, opts.publicKeyFetcher)
			if err != nil {
				return nil, fmt.Errorf("decode credential of presentation: %w", err)
			}

			return credDecoded, nil
		}

		// return credential in a structure format as is
		return cred, nil
	}

	switch cred := rawCred.(type) {
	case []interface{}:
		// 1 or more credentials
		creds := make([]interface{}, len(cred))

		for i := range cred {
			c, err := marshalSingleCredFn(cred[i])
			if err != nil {
				return nil, err
			}

			creds[i] = c
		}

		return creds, nil
	default:
		// single credential
		c, err := marshalSingleCredFn(cred)
		if err != nil {
			return nil, err
		}

		return []interface{}{c}, nil
	}
}

func validatePresentation(data []byte) error {
	loader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(basePresentationSchemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable presentation")
		return errors.New(errMsg)
	}

	return nil
}

func decodeRawPresentation(vpData []byte, vpOpts *presentationOpts) ([]byte, *rawPresentation, error) {
	if isJWS(vpData) {
		if vpOpts.publicKeyFetcher == nil {
			return nil, nil, errors.New("public key fetcher is not defined")
		}

		vcDataFromJwt, rawCred, err := decodeVPFromJWS(vpData, !vpOpts.disabledProofCheck, vpOpts.publicKeyFetcher)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from JWS: %w", err)
		}

		return vcDataFromJwt, rawCred, nil
	}

	if isJWTUnsecured(vpData) {
		rawBytes, rawCred, err := decodeVPFromUnsecuredJWT(vpData)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from unsecured JWT: %w", err)
		}

		return rawBytes, rawCred, nil
	}

	vpBytes, vpRaw, err := decodeVPFromJSON(vpData)
	if err != nil {
		return nil, nil, err
	}

	// check that embedded proof is present, if not, it's not a verifiable presentation
	if !vpOpts.disabledProofCheck && vpRaw.Proof == nil {
		return nil, nil, errors.New("embedded proof is missing")
	}

	return vpBytes, vpRaw, err
}

func decodeVPFromJSON(vpData []byte) ([]byte, *rawPresentation, error) {
	// unmarshal VP from JSON
	raw := new(rawPresentation)

	err := json.Unmarshal(vpData, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshalling of verifiable presentation: %w", err)
	}

	return vpData, raw, nil
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{}
}
