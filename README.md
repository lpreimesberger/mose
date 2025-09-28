# MOSE

MOSE (MOdular Signing and Encryption) is a Go library for signing and verifying data using ML-DSA-87 (mldsa87), a post-quantum signature scheme.

It was made out of frustration with JOSE and the slowness in getting PQC standards for basic things.

If you need to sign/check JSON data with PQC, this is it for now.

## Installation

```bash
go get github.com/lpreimesberger/mose
```

## Usage

### Signing

```go
package main

import (
	"fmt"

	"github.com/lpreimesberger/mose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"crypto/rand"
)

func main() {
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
		fmt.Println("Error generating key:", err)
		return
	}

	// Sign the data.
	signedString, err := mose.Sign(data, sk)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	fmt.Println("Signed string:", signedString)
}
```

### Verifying

```go
package main

import (
	"fmt"

	"github.com/lpreimesberger/mose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"crypto/rand"
)

func main() {
	// Signed string from the signing example.
	signedString := "..."

	// Public key from the signing example.
	pk := &mldsa87.PublicKey{}

	// Verify the signature.
	data, err := mose.CheckAndUnwrap(signedString, pk)
	if err != nil {
		fmt.Println("Error checking and unwrapping data:", err)
		return
	}

	fmt.Println("Original data:", data)
}
```
