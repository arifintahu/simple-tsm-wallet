package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/ripemd160"
)

func loadClient(credsFile string) (tsm.ECDSAClient, error) {
	credentials, err := ioutil.ReadFile(credsFile)
	if err != nil {
		return tsm.ECDSAClient{}, err
	}

	tsmClient, err := tsm.NewPasswordClientFromEncoding(string(credentials))
	if err != nil {
		return tsm.ECDSAClient{}, err
	}
	return tsm.NewECDSAClient(tsmClient), nil
}

func loadKey(keyFile string) (string, error) {
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(key)), nil
}

func getCompressedPubKeyECDSA(publicKey *ecdsa.PublicKey) []byte {
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	compressedPublicKey := make([]byte, 1+len(xBytes))
	ySignFlag := yBytes[len(yBytes)-1] % 2
	compressedPublicKey[0] = 2 | ySignFlag
	copy(compressedPublicKey[1:], xBytes)

	return compressedPublicKey
}

const PubKeySize = 33

func getAccAddressFromPubKeyECDSA(pubKey []byte) (string, error) {
	if len(pubKey) != PubKeySize {
		return "", errors.New("length of pubkey is incorrect")
	}

	sha := sha256.Sum256(pubKey)
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha[:])

	return sdk.AccAddress(hasherRIPEMD160.Sum(nil)).String(), nil
}

func main() {
	// Load client
	ecdsaClient, err := loadClient("sepior.creds.json")
	if err != nil {
		log.Fatal(err)
	}

	// Load key
	keyID, nil := loadKey("key.txt")
	if err != nil {
		log.Fatal(err)
	}

	// Get derivative public key
	chainPath := []uint32{1, 2, 3}
	derPublicKey, err := ecdsaClient.PublicKey(keyID, chainPath)
	if err != nil {
		log.Fatal(err)
	}

	// Get public key
	publicKey, err := ecdsaClient.ParsePublicKey(derPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Get compressed public key
	compressedPublicKey := getCompressedPubKeyECDSA(publicKey)
	fmt.Printf("PubKey: %s\n", hex.EncodeToString(compressedPublicKey))

	// Get account address
	accAddress, err := getAccAddressFromPubKeyECDSA(compressedPublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account Address: %s\n", accAddress)

	// Sign message
	message := []byte(`Hello World 123`)
	hash := sha256.Sum256(message)
	signature, _, err := ecdsaClient.Sign(keyID, chainPath, hash[:])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))
}
