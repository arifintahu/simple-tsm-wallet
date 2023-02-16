package client

import (
	"io/ioutil"
	"strings"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

type tsmClient struct {
	EcdsaClient tsm.ECDSAClient
	KeyID       string
}

func NewECDSAClientFromFile(credsFile string, keyFile string) (tsmClient, error) {
	credentials, err := ioutil.ReadFile(credsFile)
	if err != nil {
		return tsmClient{}, err
	}

	client, err := tsm.NewPasswordClientFromEncoding(string(credentials))
	if err != nil {
		return tsmClient{}, err
	}
	ecdsaClient := tsm.NewECDSAClient(client)

	var keyID string
	if keyFile == "" {
		keyID, err = ecdsaClient.Keygen("secp256k1")
		if err != nil {
			return tsmClient{}, err
		}
	} else {
		key, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return tsmClient{}, err
		}

		keyID = strings.TrimSpace(string(key))
	}

	return tsmClient{
		EcdsaClient: ecdsaClient,
		KeyID:       keyID,
	}, nil
}
