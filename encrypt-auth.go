package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"

	//"crypto/rand"
	//"io"
	//"math/big"
	//"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func CalcPS(x []byte) []byte {
	var PS []byte
	n := len(x) % 16
	if n != 0 {
		temp := make([]byte, 16-n)
		for i := 0; i < 16-n; i++ {
			temp[i] = byte(16 - n)
		}
		PS = temp
	} else {
		temp := make([]byte, 16)
		for i := range temp {
			temp[i] = byte(16)
		}
		PS = temp
	}
	return PS
}

func writeToFile(fileName string, data []byte) {
	var stringData string
	for _, n := range data {
		str := strconv.FormatUint(uint64(n), 2)
		for len(str) != 8 {
			str = "0" + str
		}
		stringData += str
	}

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("error creating file")
		return
	}
	defer file.Close()

	_, err = file.WriteString(stringData)
	if err != nil {
		fmt.Println("error writing to file")
		return
	}
}

func HMAC_SHA256(MACKeySlice []byte, lineBytes []byte) []byte {
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

func encrypt(lineBytes []byte, MACKeySlice []byte, encryptionKeySlice []byte) {
	HMACTag := HMAC_SHA256(MACKeySlice, lineBytes)

	messagePrime := append(lineBytes, HMACTag...)

	messageDoublePrime := append(messagePrime, CalcPS(messagePrime)...)

	//Init AES Block being used with encryption key given.
	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		return
	}
	//Initialize AES-CBC
	var initializationVector []byte
	for i:=0; i < 16; i++ {
		temp, _ := rand.Int(rand.Reader, big.NewInt(256))
		initializationVector = append(initializationVector, temp.Bytes()...)
	}
	firstPlainBlockBytes := messageDoublePrime[0:16]
	firstPlainBlock := new(big.Int).SetBytes(firstPlainBlockBytes)
	XORFirstBlock := new(big.Int).Xor(firstPlainBlock, new(big.Int).SetBytes(initializationVector))
	XORFirstBlockSlice := XORFirstBlock.Bytes()
	//Do first round of encryption...destination of ciphertext block is encryptedSlice
	encryptedSlice := make([]byte, AESBlock.BlockSize())

	AESBlock.Encrypt(encryptedSlice, XORFirstBlockSlice)

	//Theoretically the size of info put into the XOR slice should not change
	XORSlice := make([]byte, AESBlock.BlockSize())
	copy(XORSlice, encryptedSlice)

	//Repeat previous AES-CBC procedure for rest of plaintext if needed
	for i := 16; i < len(messageDoublePrime); i += 16 {
		plainBlockBytes := messageDoublePrime[i : i+16]
		plainBlock := new(big.Int).SetBytes(plainBlockBytes)
		bigXORSlice := new(big.Int).SetBytes(XORSlice)
		XORBlock := new(big.Int).Xor(plainBlock, bigXORSlice)
		XORBlockSlice := XORBlock.Bytes()

		AESBlock.Encrypt(XORSlice, XORBlockSlice)
		encryptedSlice = append(encryptedSlice, XORSlice...)
	}

	ciphertext := append(initializationVector, encryptedSlice...)
	writeToFile(os.Args[7], ciphertext)
}

func decrypt(lineBytes []byte, MACKeySlice []byte, encryptionKeySlice []byte) {
	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		return
	}
	//Decrypt first block of ciphertext
	initVector := lineBytes[0:16]
	cipherTextBlock := lineBytes[16:32]
	prePlainText := make([]byte, AESBlock.BlockSize())
	AESBlock.Decrypt(prePlainText, cipherTextBlock)
	//XOR initvec and preplaintext for plaintext
	messageDoublePrimeInt := new(big.Int).Xor(new(big.Int).SetBytes(initVector), new(big.Int).SetBytes(prePlainText))
	messageDoublePrime := messageDoublePrimeInt.Bytes()

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
	n := messageDoublePrime[len(messageDoublePrime)-1]

	for i := len(messageDoublePrime) - int(n); i < len(messageDoublePrime); i++ {
		if int(n) != int(messageDoublePrime[i]) {
			fmt.Println("INVALID PADDING")
			os.Exit(1)
		}
	}
	messagePrime := messageDoublePrime[:len(messageDoublePrime)-int(n)]
	fmt.Println(messagePrime)

	plainText := messagePrime[:len(messagePrime)-32]
	//Check if MAC tags are matching
	HMACTag := messagePrime[len(messagePrime)-32:]
	actualHMACTag := HMAC_SHA256(MACKeySlice, plainText)
	if bytes.Compare(HMACTag, actualHMACTag) != 0 {
		fmt.Println("INVALID MAC")
		os.Exit(2)
	} else {
		writeToFile(os.Args[7], plainText)
	}

}

func main() {
	var encryptMode bool
	/** This section of code is to take in command line params and make sure all params are there. */
	if len(os.Args) < 8 {
		fmt.Fprintln(os.Stderr, "Please give all params!")
		return
	}

	if os.Args[1] == "encrypt" {
		encryptMode = true
	} else if os.Args[1] == "decrypt" {
		encryptMode = false
	} else {
		fmt.Print("Give valid mode please.")
		return
	}
	if os.Args[2] != "-k" || os.Args[4] != "-i" || os.Args[6] != "-o" {
		fmt.Print("Invalid input")
		return
	}

	decode, err := hex.DecodeString(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	if len(decode) != 32 {
		fmt.Println("Please give 32 byte key")
		return
	}
	MACKeySlice := decode[:16]
	encryptionKeySlice := decode[16:]

	lines, err := ioutil.ReadFile(os.Args[5])
	if err != nil {
		os.Exit(1)
	}
	text := strings.TrimSpace(string(lines))
	text = strings.Replace(text, " ", "", -1)
	//fmt.Println(text)
	var lineBytes []byte
	for i :=0; i < len(text); i += 8 {
		value, _ := strconv.ParseUint(text[i:i+8], 2, 8)
		lineBytes = append(lineBytes, byte(value))
	}

	if encryptMode {
		encrypt(lineBytes, MACKeySlice, encryptionKeySlice)
	} else {
		decrypt(lineBytes, MACKeySlice, encryptionKeySlice)
	}

}
