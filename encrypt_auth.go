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
	//messagePrime := make([]byte, len(lineBytes))
	//copy(messagePrime, lineBytes)
	//for _, n := range HMACTag {
	//	x := int64(n)
	//	binary := strconv.FormatInt(x, 2) + " "
	//	fmt.Println([]byte(binary))
	//	fmt.Println(binary)
	//	messagePrime = append(messagePrime, []byte(binary)...)
	//}

	messagePrime := append(lineBytes, HMACTag...)
	//fmt.Println(string(lineBytes))
	//writeToFile(os.Args[7], messagePrime)

	fmt.Println("MessagePrime: ")
	fmt.Println(messagePrime)
	messageDoublePrime := append(messagePrime, CalcPS(messagePrime)...)

	//Init AES Block being used with encryption key given.
	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		return
	}
	//Initialize AES-CBC
	//var count int
	//var initializationVector *big.Int
	//for count != 16 {
	//	temp, _ := rand.Int(rand.Reader, big.NewInt(65536))
	//	for _, x := range temp.Bits() {
	//		for x != 0 {
	//			x &= x - 1
	//			count++
	//		}
	//		count++
	//	}
	//	temp.Bits()
	//	initializationVector = temp
	//}
	var initializationVector []byte
	for i:=0; i < 16; i++ {
		temp, _ := rand.Int(rand.Reader, big.NewInt(256))
		initializationVector = append(initializationVector, temp.Bytes()...)
	}
	//fmt.Printf("LENGTH OF INITVECTOR: %d", len(initializationVector))

	//initializationVector, _ := rand.Int(rand.Reader, 256)

	fmt.Println(initializationVector)
	//fmt.Printf("%b", initializationVector)
	fmt.Println(messageDoublePrime)
	firstPlainBlockBytes := messageDoublePrime[0:16]
	firstPlainBlock := new(big.Int).SetBytes(firstPlainBlockBytes)
	XORFirstBlock := new(big.Int).Xor(firstPlainBlock, new(big.Int).SetBytes(initializationVector))
	XORFirstBlockSlice := XORFirstBlock.Bytes()
	//Do first round of encryption...destination of ciphertext block is encryptedSlice
	encryptedSlice := make([]byte, AESBlock.BlockSize())
	//fmt.Printf("XORBLOCK SLICE SIZE: %d \n\n", len(XORFirstBlockSlice))

	AESBlock.Encrypt(encryptedSlice, XORFirstBlockSlice)

	//Theoretically the size of info put into the XOR slice should not change
	XORSlice := make([]byte, AESBlock.BlockSize())
	copy(XORSlice, encryptedSlice)

	fmt.Printf("msgDoublePrime length mod 16: %d\n", len(messageDoublePrime)%16)
	//Repeat previous AES-CBC procedure for rest of plaintext if needed
	for i := 16; i <= len(messageDoublePrime); i += 16 {
		plainBlockBytes := messageDoublePrime[i : i+16]
		plainBlock := new(big.Int).SetBytes(plainBlockBytes)
		bigXORSlice := new(big.Int).SetBytes(XORSlice)
		XORBlock := new(big.Int).Xor(plainBlock, bigXORSlice)
		XORBlockSlice := XORBlock.Bytes()

		//fmt.Println(len(XORBlockSlice))
		AESBlock.Encrypt(XORSlice, XORBlockSlice)
		encryptedSlice = append(encryptedSlice, XORSlice...)
	}

	ciphertext := append(initializationVector, encryptedSlice...)
	fmt.Println(ciphertext)
	writeToFile(os.Args[7], ciphertext)
}

func decrypt(lineBytes []byte, MACKeySlice []byte, encryptionKeySlice []byte) {
	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		return
	}
	//fmt.Println(lineBytes)
	//Decrypt first block of ciphertext
	initVector := lineBytes[0:16]
	cipherTextBlock := lineBytes[16:32]
	prePlainText := make([]byte, AESBlock.BlockSize())
	AESBlock.Decrypt(prePlainText, cipherTextBlock)
	//XOR initvec and preplaintext for plaintext
	//messageDoublePrime := make([]byte, AESBlock.BlockSize())
	//for i, _ := range prePlainText {
	//	messageDoublePrime[i] = initVector[i] ^ prePlainText[i]
	//}
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
	//fmt.Println(messageDoublePrime)

	//Check that padding is structured correctly
	n := messageDoublePrime[len(messageDoublePrime)-1]
	//fmt.Println(n)

	for i := len(messageDoublePrime) - int(n); i < len(messageDoublePrime); i++ {
		if int(n) != int(messageDoublePrime[i]) {
			fmt.Println("INVALID PADDING")
			os.Exit(1)
		}
	}
	messagePrime := messageDoublePrime[:len(messageDoublePrime)-int(n)]
	plainText := messagePrime[:len(messagePrime)-32]
	//Check if MAC tags are matching
	HMACTag := messagePrime[len(messagePrime)-32:]
	actualHMACTag := HMAC_SHA256(MACKeySlice, lineBytes)
	if bytes.Compare(HMACTag, actualHMACTag) != 0 {
		fmt.Println("INVALID MAC")
		os.Exit(2)
	} else {
		writeToFile(os.Args[7], plainText)
	}

	//writeToFile(os.Args[7], plainText)

}

func main() {
	var encryptMode bool
	//var encryptionKey uint64
	//var MACKey uint64
	//var input string
	//var outFile string

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
	//fmt.Println(decode)
	if len(decode) != 32 {
		fmt.Println("Please give 32 byte key")
		return
	}
	MACKeySlice := decode[:16]
	encryptionKeySlice := decode[16:]

	//fmt.Println(MACKeySlice)
	//fmt.Println(encryptionKeySlice)

	//TODO: CHECK THIS IS GOOD?!?!?!
	//encryptionKey = binary.BigEndian.Uint64(encryptionKeySlice)
	//MACKey = binary.BigEndian.Uint64(MACKeySlice)
	//fmt.Println(encryptionKey)
	//fmt.Println(MACKey)

	//var lineBytes []byte
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
	//var byteLines []byte

	//buf := bytes.NewReader(lines)
	//err = binary.Read(buf, binary.LittleEndian, &lineBytes)
	//if err != nil {
	//	os.Exit(1)
	//}
	//
	//fmt.Println(lines)

	if encryptMode {
		encrypt(lineBytes, MACKeySlice, encryptionKeySlice)
	} else {
		decrypt(lineBytes, MACKeySlice, encryptionKeySlice)
	}

	//secondHashInput := make([]byte, len(firstHash))
	//HMACResult := append(outerPadding, []byte(secondHash)...)

	//fmt.Println(len(os.Args), os.Args)

	//for _, x := range os.Args {
	//	fmt.Println(x)
	//}

	//var lines []string
	//scanner := bufio.NewScanner(os.Stdin)
	//for scanner.Scan() {
	//	lines = append(lines, scanner.Text())
	//}
	//
	//for _, x := range lines {
	//	fmt.Printf(x + "\n")
	//}

}
