package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	txclient "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
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

func getKeyTestFromPriv() (cryptotypes.PrivKey, cryptotypes.PubKey, sdk.AccAddress) {
	privEncoded := "9bc7606d8e589c43c4587023b03dc88a3c21d49383e9ebececd9798ced01dbe1"
	priv, err := hex.DecodeString(privEncoded)
	if err != nil {
		log.Fatal(err)
	}
	key := secp256k1.PrivKey{
		Key: priv,
	}
	pub := key.PubKey()
	addr := sdk.AccAddress(pub.Address())
	return &key, pub, addr
}

func main() {
	priv1, _, addr1 := getKeyTestFromPriv()
	fmt.Println(addr1.String())

	// Send tx
	encCfg := simapp.MakeTestEncodingConfig()
	txBuilder := encCfg.TxConfig.NewTxBuilder()

	fromAddr := addr1
	toAddr := sdk.MustAccAddressFromBech32("cosmos13rqh69lwlgggayv30d0243jknsdlhz3757sqz8")
	amount := sdk.NewCoins(sdk.NewInt64Coin("uatom", 1000))
	msg := banktypes.NewMsgSend(fromAddr, toAddr, amount)

	err := txBuilder.SetMsgs(msg)
	if err != nil {
		log.Fatal(err)
	}

	txBuilder.SetGasLimit(200000)
	txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("uatom", 1000)))
	txBuilder.SetMemo("tsm sdk")
	// txBuilder.SetTimeoutHeight(3)

	// First round: we gather all the signer infos. We use the "set empty
	// signature" hack to do that.
	var accSeq uint64 = 1
	var accNumber uint64 = 724141
	var sigsV2 []signing.SignatureV2

	sigV2 := signing.SignatureV2{
		PubKey: priv1.PubKey(),
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

	sigV2, err = txclient.SignWithPrivKey(
		encCfg.TxConfig.SignModeHandler().DefaultMode(), signerData,
		txBuilder, priv1, encCfg.TxConfig, accSeq,
	)
	if err != nil {
		log.Fatal(err)
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
	fmt.Println(base64.StdEncoding.EncodeToString(txBytes))

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
