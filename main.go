package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gcash/bchd/bchec"
	"github.com/sasaxie/go-client-api/common/base58"
	"golang.org/x/crypto/sha3"
	"log"
	"os"

	"math/big"
)

/*
	Tron Address Algorithm
	https://developers.tron.network/docs/account
*/
var (
	Log *log.Logger
)

func main() {
	// Use the ECDSA crypto library to generate the Tron Address
	var logpath = "./tronaddr.log"
	var file, err1 = os.Create(logpath)

	if err1 != nil {
		panic(err1)
	}
	Log = log.New(file, "", log.LstdFlags|log.Lshortfile)
	Log.Println("LogFile : " + logpath)

	for true {
		addr := generateNewKey()
		subAddr := addr[len(addr)-8:]
		if subAddr == "88888888" {
			break
		}
	}

	// Using a hex of a private key extract the Tron Address
	//addressFromKey("F43EBCC94E6C257EDBE559183D1A8778B2D5A08040902C0F0A77A3343A1D0EA5") // TWVRXXN5tsggjUCDmqbJ4KxPdJKQiynaG6
	//addressFromKey("a24c37ec71cfc4046f617b5011f932c994c863e20ad3b8a20b21a4de943279dd") // TXA74MA1z4669rLBKmJB16AvHxppTLJCdT
	//addressFromKey("e36ace9ad7486f6149790e2a95a2a53fe57454b7a083093a0049457baebbabcf") // TKfSBdtyTikWF5XCRdxqNktif3UShzS4ke
}

var generateCont = 0

func generateNewKey() (addr string) {

	if generateCont%100 == 0 {
		fmt.Println("******************* New Key Using ECDSA *******************", generateCont)

	}

	generateCont++

	// Generate a new key using the ECDSA library
	// #1
	key, _ := ecdsa.GenerateKey(bchec.S256(), rand.Reader)
	priv := key.D.Bytes()
	pubX := key.X.Bytes()
	pubY := key.Y.Bytes()
	pub := append(pubX, pubY...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr := base58.Encode(rawAddr)

	subAddr := tronAddr[len(tronAddr)-8:]
	if subAddr == "88888888" {
		Log.Println("Private key: (" + fmt.Sprintf("%d", len(priv)) + ") " + fmt.Sprintf("%x", priv))
		Log.Println("tronAddr: (" + fmt.Sprintf("%d", len(tronAddr)) + ") " + tronAddr)
		Log.Println("******************* New Key Using ECDSA *******************")
	}

	return string(tronAddr)

}

func addressFromKey(keyStr string) {
	fmt.Println("******************* Get Address from Key *******************")

	// Build the Private Key and extract the Public Key
	keyBytes, _ := hex.DecodeString(keyStr)
	key := new(ecdsa.PrivateKey)
	key.PublicKey.Curve = bchec.S256()
	key.D = new(big.Int).SetBytes(keyBytes)
	key.PublicKey.X, key.PublicKey.Y = key.PublicKey.Curve.ScalarBaseMult(keyBytes)

	// #1
	pub := append(key.X.Bytes(), key.Y.Bytes()...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr := base58.Encode(rawAddr)

	Log.Println("Private key: (" + fmt.Sprintf("%d", len(keyBytes)) + ") " + fmt.Sprintf("%x", keyBytes))
	Log.Println("tronAddr: (" + fmt.Sprintf("%d", len(tronAddr)) + ") " + tronAddr)

	Log.Println("******************* Get Address from Key *******************")
}
