package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func main() {

	credentials, err := ioutil.ReadFile("sepior.creds.json")
	if err != nil {
		log.Fatal(err)
	}

	// Create ECDSA client from credentials

	tsmClient, err := tsm.NewPasswordClientFromEncoding(string(credentials))
	if err != nil {
		log.Fatal(err)
	}
	ecdsaClient := tsm.NewECDSAClient(tsmClient) // ECDSA with secp256k1 curve

	// Generate ECDSA key

	keyID, err := ecdsaClient.Keygen("secp256k1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key: ID=%s\n", keyID)

	// Get the public key as a DER encoding

	derPubKey, err := ecdsaClient.PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	// We can now sign with the created key

	message := []byte(`Hello World`)
	hash := sha256.Sum256(message)
	derSignature, _, err := ecdsaClient.Sign(keyID, nil, hash[:])
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature relative to the signed message and the public key

	err = tsm.ECDSAVerify(derPubKey, hash[:], derSignature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("PubKey: %s\n", hex.EncodeToString(derPubKey))
	fmt.Printf("Signature: %s\n", hex.EncodeToString(derSignature))
}
