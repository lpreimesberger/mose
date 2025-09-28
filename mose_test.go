// Copyright (c) 2025 Caprica LLC
// SPDX-License-Identifier: Apache-2.0

package mose

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestSignAndCheck(t *testing.T) {
	// Create a sample struct.
	type MyData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	data := MyData{
		Name:  "test",
		Value: 123,
	}

	// Generate a new key pair for ML-DSA-87.
	pk, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Error generating key:", err)
	}

	// Sign the data.
	signedString, err := Sign(data, sk)
	if err != nil {
		t.Fatal("Error signing data:", err)
	}

	// Verify the signature.
	_, err = CheckAndUnwrap(signedString, pk)
	if err != nil {
		t.Fatal("Error checking and unwrapping data:", err)
	}
}