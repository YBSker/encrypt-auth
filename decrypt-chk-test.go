package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func simpleTestCheckSum(message []byte) byte {
	checkSum := 0
	for i, _ := range message {
		checkSum += int(message[i])
	}
	return byte(checkSum % 256)
}

func decryptTestCheck(message []byte, encryptionKey []byte) string {
	var initializationVector []byte
	initializationVector = append(initializationVector, message[:16]...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		fmt.Println("Error in getting aes block")
		os.Exit(0)
	}
	//fmt.Println(message[16:])

	stream := cipher.NewCTR(block, initializationVector)
	messagePrime := make([]byte, len(message[16:]))
	//TODO SMTH GOES WRONG HEREE
	stream.XORKeyStream(messagePrime, message[16:])
	//fmt.Println("THIS IS MESSAGE PRIME")
	//fmt.Println(messagePrime)

	plainText := messagePrime[1:]
	//fmt.Println("THIS IS PLAINTEXT")
	//fmt.Println(plainText)
	tag := messagePrime[0]
	//fmt.Println(messagePrime)
	//fmt.Println(tag)

	//if int(messagePrime[1]) % 256 == 0 {
	//	fmt.Println("HALLELUJAH THE GOD IS REAL FUCK FUCK FUCK FUCK FUCK FUCK FUCK")
	//	fmt.Println(messagePrime)
	//}
	var stringData string
	//fmt.Println("THIS IS CHECKSUM VAL")

	//fmt.Println(simpleTestCheckSum(plainText))
	//fmt.Println(plainText)
	//fmt.Println(tag)
	//fmt.Println(simpleTestCheckSum(plainText))
	if tag != simpleTestCheckSum(plainText) {
		fmt.Println("INVALID CHECKSUM")
		os.Exit(0)
	} else {
		//fmt.Println("WE GOT ONE BOYS WE REALLY FUCKING DID GOD BLESS AMERICA")
		for _, n := range plainText {
			str := strconv.FormatUint(uint64(n), 2)
			for len(str) != 8 {
				str = "0" + str
			}
			stringData += str
		}
	}

	return stringData
}

func main() {
	//TODO: actually fuckit
	if len(os.Args) < 3 {
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
	for i := 0; i < len(text); i += 8 {
		value, _ := strconv.ParseUint(text[i:i+8], 2, 8)
		lineBytes = append(lineBytes, byte(value))
	}

	hardKey, _ := hex.DecodeString("59454c4c4f57205355424d4152494e454")
	//if err != nil {
	//	log.Fatal(err)
	//}

	if len(hardKey) != 16 {
		fmt.Println("Please give 16 byte encryption key")
		return
	}


	decryptedCipherText := decryptTestCheck(lineBytes, hardKey)

	//Get the proposed decryption from os.Pipe
	//fmt.Println("reading pipe")
	//r,_,_ := os.Pipe()
	//proposedDecryption ,_ := ioutil.ReadAll(r)
	//fmt.Println(" pipe read")
	//reader := bufio.NewReader(os.Stdin)
	//proposedDecryption, _ := reader.ReadString('\n')

	proposedDecrypt, _ := ioutil.ReadFile("checksumDecryptAttempt.txt")
	//if err != nil {
	//	os.Exit(0)
	//}
	//fmt.Println(proposedDecrypt)


	proposedDecrypttext := strings.TrimSpace(string(proposedDecrypt))
	proposedDecrypttext = strings.Replace(proposedDecrypttext, " ", "", -1)

	var proposedDecryptBytes []byte
	for i := 0; i < len(proposedDecrypttext); i += 8 {
		value, _ := strconv.ParseUint(proposedDecrypttext[i:i+8], 2, 8)
		proposedDecryptBytes = append(proposedDecryptBytes, byte(value))
	}
	//fmt.Println(string(proposedDecryptBytes))

	//fmt.Println("APAIROFNUMBERS")
	//fmt.Println(decryptedCipherText)
	//fmt.Println(proposedDecrypttext)

	if decryptedCipherText == proposedDecrypttext {
		fmt.Print("SUCCESS")
		os.Exit(0)
	}

	decryptTestCheck(proposedDecryptBytes, hardKey)

	//fmt.Println("WHAT THE FUCK we got to the end")

}