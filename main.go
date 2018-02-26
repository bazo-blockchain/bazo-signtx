package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("Usage: bazo-signtx <txHash> <keyfile>")
	}

	filehandle, err := os.Open(os.Args[2])
	if err != nil {
		log.Fatal("Cannot open file.")
	}

	reader := bufio.NewReader(filehandle)

	//Public Key
	pub1, err1 := reader.ReadString('\n')
	pub2, err2 := reader.ReadString('\n')
	//Private Key
	priv, err3 := reader.ReadString('\n')
	if err1 != nil || err2 != nil || err3 != nil {
		log.Fatal(fmt.Printf("Could not read key from file: %v\n", err))
	}

	pub1Int, b1 := new(big.Int).SetString(strings.Split(pub1, "\n")[0], 16)
	pub2Int, b2 := new(big.Int).SetString(strings.Split(pub2, "\n")[0], 16)
	privInt, b3 := new(big.Int).SetString(strings.Split(priv, "\n")[0], 16)
	if !b1 || !b2 || !b3 {
		log.Fatal("Failed to convert the key strings to big.Int.")
	}

	pubKey := ecdsa.PublicKey{
		elliptic.P256(),
		pub1Int,
		pub2Int,
	}

	privKey := ecdsa.PrivateKey{
		pubKey,
		privInt,
	}

	//Sign tx with private key
	var txHash [32]byte
	var txSig [64]byte

	txHashInt, b := new(big.Int).SetString(os.Args[1], 16)
	if !b {
		log.Fatal("Failed to convert the txHash to big.Int.")
	}

	copy(txHash[:], txHashInt.Bytes())

	r, s, _ := ecdsa.Sign(rand.Reader, &privKey, txHash[:])

	copy(txSig[32-len(r.Bytes()):32], r.Bytes())
	copy(txSig[64-len(s.Bytes()):], s.Bytes())

	fmt.Printf("Tx Signature: %x\n", txSig)
}
