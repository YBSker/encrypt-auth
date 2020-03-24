package main

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
)


func HMAC_SHA256Test(MACKeySlice []byte, lineBytes []byte) []byte {
	hash := sha256.New()

	innerPadding := make([]byte, 64)
	outerPadding := make([]byte, 64)
	i := 0
	//hmac reset part in rfc4634
	for ; i < len(MACKeySlice); i++ {
		innerPadding[i] = MACKeySlice[i] ^ 0x36
		outerPadding[i] = MACKeySlice[i] ^ 0x5c
	}
	for ; i < 64; i++ {
		innerPadding[i] = 0x36
		outerPadding[i] = 0x5c
	}
	firstHashInput := append(innerPadding, lineBytes...)
	hash.Write(firstHashInput)
	secondHashInput := append(outerPadding, hash.Sum(nil)...)
	hash.Write(secondHashInput)
	HMACTag := hash.Sum(nil)
	return HMACTag
}

func decryptTest(lineBytes []byte, hardKey []byte, hardcode bool) string {
	//fmt.Println("we got in here")
	MACKeySlice := hardKey[:16]
	encryptionKeySlice := hardKey[16:]

	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		os.Exit(0)
	}
	//Decrypt first block of ciphertext
	initVector := lineBytes[0:16]
	cipherTextBlock := lineBytes[16:32]
	prePlainText := make([]byte, AESBlock.BlockSize())
	AESBlock.Decrypt(prePlainText, cipherTextBlock)
	//XOR initvec and preplaintext for plaintext
	messageDoublePrimeInt := new(big.Int).Xor(new(big.Int).SetBytes(initVector), new(big.Int).SetBytes(prePlainText))
	messageDoublePrime := messageDoublePrimeInt.Bytes()

	//if !hardcode {
	//	fmt.Println(messageDoublePrime)
	//}


	//Decrypt the rest of the ciphertext
	for i := 32; i < len(lineBytes); i += 16 {
		XORTextBlock := lineBytes[i-16 : i]
		cipherText := lineBytes[i : i+16]
		AESBlock.Decrypt(prePlainText, cipherText)
		//temp := make([]byte, AESBlock.BlockSize())
		//for i, _ := range prePlainText {
		//	temp[i] = XORTextBlock[i] ^ prePlainText[i]
		//}
		tempInt := new(big.Int).Xor(new(big.Int).SetBytes(XORTextBlock), new(big.Int).SetBytes(prePlainText))
		temp := tempInt.Bytes()

		messageDoublePrime = append(messageDoublePrime, temp...)
	}

	//Check that padding is structured correctly
	//if !hardcode {
	//	fmt.Println(messageDoublePrime)
	//}
	n := messageDoublePrime[len(messageDoublePrime)-1]

	//if !hardcode {
	//		fmt.Println(n)
	//		//fmt.Println(messageDoublePrime)
	//	}

	if n > 16 || n == 0 {
		fmt.Println("INVALID PADDING")
		os.Exit(0)
	}




	for i := len(messageDoublePrime) - int(n); i < len(messageDoublePrime); i++ {
		if int(n) != int(messageDoublePrime[i]) {
			fmt.Println("INVALID PADDING")
			os.Exit(0)
		}
	}
	messagePrime := messageDoublePrime[:len(messageDoublePrime)-int(n)]
	plainText := messagePrime[:len(messagePrime)-32]
	//Check if MAC tags are matching
	HMACTag := messagePrime[len(messagePrime)-32:]
	actualHMACTag := HMAC_SHA256Test(MACKeySlice, plainText)
	var stringData string
	if bytes.Compare(HMACTag, actualHMACTag) != 0 {
		fmt.Println("INVALID MAC")
		os.Exit(0)
	} else {
		for _, n := range plainText {
			str := strconv.FormatUint(uint64(n), 2)
			for len(str) != 8 {
				str = "0" + str
			}
			stringData += str
		}
	}
	if !hardcode {
		fmt.Println("SUCCESS")
		os.Exit(0)
	}
	return stringData
}

func main() {
	//TODO: actually fuckit
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Please give all params!")
		return
	}

	if os.Args[1] != "-i" {
		os.Exit(0)
	}

	lines, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		os.Exit(0)
	}
	text := strings.TrimSpace(string(lines))
	text = strings.Replace(text, " ", "", -1)
	var lineBytes []byte
	for i :=0; i < len(text); i += 8 {
		value, _ := strconv.ParseUint(text[i:i+8], 2, 8)
		lineBytes = append(lineBytes, byte(value))
	}

	hardKey, err := hex.DecodeString("59454c4c4f57205355424d4152494e4543415453434153532321545343415453")
	if err != nil {
		log.Fatal(err)
	}
	if len(hardKey) != 32 {
		fmt.Println("Please give 32 byte key")
		return
	}


	decryptedCipherText := decryptTest(lineBytes, hardKey, true)
	//Get the proposed decryption from os.Pipe
	//fmt.Println("reading pipe")
	//r,_,_ := os.Pipe()
	//proposedDecryption ,_ := ioutil.ReadAll(r)
	//fmt.Println(" pipe read")
	//reader := bufio.NewReader(os.Stdin)
	//proposedDecryption, _ := reader.ReadString('\n')

	proposedDecryption := os.Args[3]
	proposedDecryptionString := strings.TrimSpace(proposedDecryption)
	proposedDecryptionString = strings.Replace(proposedDecryptionString, " ", "", -1)



	if decryptedCipherText == proposedDecryptionString {
		fmt.Print("SUCCESS")
		os.Exit(0)
	}
	var proposedDecryptBytes []byte
	for i := 0; i < len(proposedDecryption); i += 8 {
		value, _ := strconv.ParseUint(proposedDecryption[i:i+8], 2, 8)
		proposedDecryptBytes = append(proposedDecryptBytes, byte(value))
	}

	decryptTest(proposedDecryptBytes, hardKey, false)


	//fmt.Println("WHAT THE FUCK we got to the end")

}