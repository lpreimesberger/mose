// Copyright (c) 2025 Caprica LLC
// SPDX-License-Identifier: Apache-2.0

package mose

import (
	"encoding/ascii85"
	"encoding/base64"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/go-json-experiment/json"
)

// SignedData represents the structure of the signed data.
// O is the operation, S is the signature, and D is the data.
type SignedData struct {
	O string `json:"o"`
	S string `json:"s"`
	D string `json:"d"`
}

// Sign takes an interface and a private key, and returns a signed string.
// The data is marshaled to a deterministic JSON, encoded to Base85, signed,
// and then the signature and data are wrapped in a SignedData struct, which is
// then marshaled to JSON and encoded to Base85.
func Sign(data interface{}, sk *mldsa87.PrivateKey) (string, error) {
	// 1. Marshal the input data to deterministic JSON.
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// 2. Encode the JSON to Base85.
	encodedData := make([]byte, ascii85.MaxEncodedLen(len(jsonData)))
	n := ascii85.Encode(encodedData, jsonData)
	encodedData = encodedData[:n]

	// 3. Sign the Base85 data.
	signature := make([]byte, mldsa87.SignatureSize)
	err = mldsa87.SignTo(sk, encodedData, []byte(""), false, signature)
	if err != nil {
		return "", err
	}

	// 4. Create the SignedData struct.
	signedData := SignedData{
		O: "s",
		S: base64.StdEncoding.EncodeToString(signature),
		D: string(encodedData),
	}

	// 5. Marshal the SignedData struct to JSON.
	finalJson, err := json.Marshal(signedData)
	if err != nil {
		return "", err
	}

	// 6. Encode the final JSON to Base85.
	finalEncoded := make([]byte, ascii85.MaxEncodedLen(len(finalJson)))
	n = ascii85.Encode(finalEncoded, finalJson)
	finalEncoded = finalEncoded[:n]

	return string(finalEncoded), nil
}

// CheckAndUnwrap takes a signed string and a public key, and returns the
// original data and an error if the signature is invalid.
// If the signature is invalid, it still returns the data, but with an error.
func CheckAndUnwrap(signedString string, pk *mldsa87.PublicKey) (string, error) {
	// 1. Base85 decode the input string.
	decodedSigned := make([]byte, len(signedString))
	decodedLen, _, err := ascii85.Decode(decodedSigned, []byte(signedString), true)
	if err != nil {
		return "", err
	}

	// 2. Unmarshal the JSON to a SignedData struct.
	var signedData SignedData
	err = json.Unmarshal(decodedSigned[:decodedLen], &signedData)
	if err != nil {
		return "", err
	}

	// 3. Base64 decode the signature.
	signature, err := base64.StdEncoding.DecodeString(signedData.S)
	if err != nil {
		return signedData.D, err
	}

	// 4. Verify the signature.
	if mldsa87.Verify(pk, []byte(signedData.D), []byte(""), signature) {
		// 5. If the signature is valid, return the un-Base85'd inner data and a nil error.
		return signedData.D, nil
	} else {
		// 6. If the signature is invalid, return the un-Base85'd inner data and an error.
		return signedData.D, errors.New("invalid signature")
	}
}
