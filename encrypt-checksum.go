package main

import(
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
)

func writeToFileCheckSum(fileName string, data []byte) {
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

func simpleCheckSum(message []byte) byte  {
	checkSum := 0
	for i, _ := range message {
		checkSum += int (message[i])
	}
	return byte(checkSum % 256)
}

func encryptCheckSum(encryptionKey []byte, message []byte) {
	tag := simpleCheckSum(message)
	var tagByteSlice []byte
	tagByteSlice = append(tagByteSlice, tag)
	messagePrime := append(tagByteSlice, message...)

	var initializationVector []byte
	for i:=0; i < 16; i++ {
		temp, _ := rand.Int(rand.Reader, big.NewInt(256))
		initializationVector = append(initializationVector, temp.Bytes()...)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Println("Error in getting aes block")
		os.Exit(0)
	}

	stream := cipher.NewCTR(block, initializationVector)
	ciphertext := make([]byte, len(messagePrime))
	stream.XORKeyStream(ciphertext, messagePrime)
	finalCipherText := append(initializationVector, ciphertext...)

	writeToFileCheckSum(os.Args[7], finalCipherText)
}

func decryptCheckSum(encryptionKey []byte, message []byte) {
	var initializationVector []byte
	initializationVector = append(initializationVector, message[:16]...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Println("Error in getting aes block")
		os.Exit(0)
	}

	stream := cipher.NewCTR(block, initializationVector)
	messagePrime := make([]byte, len(message[16:]))
	stream.XORKeyStream(messagePrime, message[16:])

	plainText := messagePrime[1:]
	tag := messagePrime[0]
	if tag != simpleCheckSum(plainText) {
		fmt.Println("INVALID CHECKSUM")
		os.Exit(0)
	}

	writeToFileCheckSum(os.Args[7], plainText)
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

	encryptionKeySlice, err := hex.DecodeString(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	if len(encryptionKeySlice) != 16 {
		fmt.Println("Please give 16 byte encryption key")
		return
	}

	lines, err := ioutil.ReadFile(os.Args[5])
	if err != nil {
		os.Exit(1)
	}
	text := strings.TrimSpace(string(lines))
	text = strings.Replace(text, " ", "", -1)

	var lineBytes []byte
	for i :=0; i < len(text); i += 8 {
		value, _ := strconv.ParseUint(text[i:i+8], 2, 8)
		lineBytes = append(lineBytes, byte(value))
	}

	if encryptMode {
		encryptCheckSum(encryptionKeySlice, lineBytes)
	} else {
		decryptCheckSum(encryptionKeySlice, lineBytes)
	}
}