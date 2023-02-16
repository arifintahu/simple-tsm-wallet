package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/arifintahu/simple-tsm-wallet/internal/client"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/simapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/ripemd160"
	"google.golang.org/grpc"
)

const PubKeySize = 33
const pubkeyCompressed byte = 0x2

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

func serializeCompressed(publicKey *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, PubKeySize)
	format := pubkeyCompressed
	if isOdd(publicKey.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, publicKey.X.Bytes())

}

func getAccAddressFromPubKeyECDSA(pubKey []byte) (sdk.AccAddress, error) {
	if len(pubKey) != PubKeySize {
		return sdk.AccAddress{}, errors.New("length of pubkey is incorrect")
	}

	sha := sha256.Sum256(pubKey)
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha[:])

	return sdk.AccAddress(hasherRIPEMD160.Sum(nil)), nil
}

func ASN1ParseSecp256k1Signature(signature []byte) (r, s *big.Int, err error) {
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	postfix, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}
	if len(postfix) > 0 {
		return nil, nil, errors.New("trailing bytes for ASN1 ecdsa signature")
	}
	return sig.R, sig.S, nil
}

func main() {
	// Load client
	tsmClient, err := client.NewECDSAClientFromFile("sepior.creds.json", "key.txt")
	if err != nil {
		log.Fatal(err)
	}
	ecdsaClient := tsmClient.EcdsaClient
	keyID := tsmClient.KeyID

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
	compressedPublicKey := serializeCompressed(publicKey)
	fmt.Printf("PubKey: %s\n", hex.EncodeToString(compressedPublicKey))

	// Get account address
	accAddress, err := getAccAddressFromPubKeyECDSA(compressedPublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account Address: %s\n", accAddress.String())

	// Send tx
	encCfg := simapp.MakeTestEncodingConfig()
	txBuilder := encCfg.TxConfig.NewTxBuilder()

	fromAddr := accAddress
	toAddr := sdk.MustAccAddressFromBech32("cosmos13rqh69lwlgggayv30d0243jknsdlhz3757sqz8")
	amount := sdk.NewCoins(sdk.NewInt64Coin("uatom", 1000))
	msg := banktypes.NewMsgSend(fromAddr, toAddr, amount)

	err = txBuilder.SetMsgs(msg)
	if err != nil {
		log.Fatal(err)
	}

	txBuilder.SetGasLimit(200000)
	txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("uatom", 1000)))
	txBuilder.SetMemo("tsm sdk")
	// txBuilder.SetTimeoutHeight(3)

	// First round: we gather all the signer infos. We use the "set empty
	// signature" hack to do that.
	var accSeq uint64 = 2
	var accNumber uint64 = 724114
	var sigsV2 []signing.SignatureV2

	sigV2 := signing.SignatureV2{
		PubKey: &secp256k1.PubKey{Key: compressedPublicKey},
		Data: &signing.SingleSignatureData{
			SignMode:  encCfg.TxConfig.SignModeHandler().DefaultMode(),
			Signature: []byte{},
		},
		Sequence: accSeq,
	}

	sigsV2 = append(sigsV2, sigV2)
	err = txBuilder.SetSignatures(sigsV2...)
	if err != nil {
		log.Fatal(err)
	}

	// Second round: all signer infos are set, so each signer can sign.
	sigsV2 = []signing.SignatureV2{}
	signerData := xauthsigning.SignerData{
		ChainID:       "theta-testnet-001",
		AccountNumber: accNumber,
		Sequence:      accSeq,
	}

	// Generate the bytes to be signed.
	signMode := encCfg.TxConfig.SignModeHandler().DefaultMode()
	signBytes, err := encCfg.TxConfig.SignModeHandler().GetSignBytes(signMode, signerData, txBuilder.GetTx())
	if err != nil {
		log.Fatal(err)
	}

	// Sign those bytes
	hash := sha256.Sum256(signBytes)
	signatureDER, recoveryID, err := ecdsaClient.Sign(keyID, chainPath, hash[:])
	if err != nil {
		log.Fatal(err)
	}

	r, s, err := ASN1ParseSecp256k1Signature(signatureDER)
	if err != nil {
		// handle error
	}
	signature := make([]byte, 2*32+1)
	r.FillBytes(signature[0:32])
	s.FillBytes(signature[32:64])
	signature[64] = byte(recoveryID)

	fmt.Println(len(signature[:64]))
	// Verify signature
	err = tsm.ECDSAVerify(derPublicKey, hash[:], signatureDER)
	if err != nil {
		log.Fatal(err)
	}

	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: signature[:64],
	}

	// Construct the SignatureV2 struct
	sigV2 = signing.SignatureV2{
		PubKey:   &secp256k1.PubKey{Key: compressedPublicKey},
		Data:     &sigData,
		Sequence: accSeq,
	}

	sigsV2 = append(sigsV2, sigV2)
	err = txBuilder.SetSignatures(sigsV2...)

	// Generated Protobuf-encoded bytes.
	txBytes, err := encCfg.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		log.Fatal(err)
	}

	// Generate a JSON string.
	txJSONBytes, err := encCfg.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
	if err != nil {
		log.Fatal(err)
	}
	txJSON := string(txJSONBytes)

	fmt.Println(txJSON)
	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))

	// Create a connection to the gRPC server.
	grpcConn, err := grpc.Dial(
		"sentry-02.theta-testnet.polypore.xyz:9090",
		grpc.WithInsecure(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer grpcConn.Close()

	fmt.Println(grpcConn.GetState().String())

	// Broadcast the tx via gRPC
	txClient := tx.NewServiceClient(grpcConn)
	grpcRes, err := txClient.BroadcastTx(
		context.Background(),
		&tx.BroadcastTxRequest{
			Mode:    tx.BroadcastMode_BROADCAST_MODE_SYNC,
			TxBytes: txBytes,
		},
	)
	// grpcRes, err := txClient.Simulate(
	// 	context.Background(),
	// 	&tx.SimulateRequest{
	// 		TxBytes: txBytes,
	// 	},
	// )
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TxResponse: %s\n", grpcRes.TxResponse.String())
}
