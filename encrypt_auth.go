package main

import (
	"bufio"
	"crypto/aes"
	"crypto/sha256"
	"strconv"
	//"io"
	"math/big"
	//"encoding/binary"
	"encoding/hex"
	"crypto/rand"
	"fmt"
	"log"
	"os"
)

func CalcPS(x []byte) []byte {
	var PS []byte
	n := len(x) % 16
	if n != 0 {
		temp := make([]byte, 16-n)
		for i:=0; i < 16-n; i++ {
			temp[i] = byte((16-n)*(16-n))
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
	//fmt.Println(data)
	var stringData string
	for _, n := range data {
		stringData += strconv.FormatUint(uint64(n), 2)
	}
	//fmt.Println(stringData)
	//err := ioutil.WriteFile(fileName, stringData, 0644)
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

func encrypt(lineBytes []byte, MACKeySlice []byte, encryptionKeySlice []byte) {
	hash := sha256.New()

	innerPadding := make([]byte, 64)
	outerPadding := make([]byte, 64)
	i := 0
	//hmac reset part in rfc4634
	for ; i < len(MACKeySlice); i++ {
		innerPadding[i] = MACKeySlice[i] ^ 0x36
		outerPadding[i] = MACKeySlice[i] ^ 0x5c
	}
	for ; i < 64 ; i++ {
		innerPadding[i] = 0x36
		outerPadding[i] = 0x5c
	}
	firstHashInput := append(innerPadding, lineBytes...)
	hash.Write(firstHashInput)
	secondHashInput := append(outerPadding, hash.Sum(nil)...)
	hash.Write(secondHashInput)
	HMACTag := hash.Sum(nil)

	messagePrime := append(lineBytes, HMACTag...)
	messageDoublePrime := append(messagePrime, CalcPS(messagePrime)...)

	//Init AES Block being used with encryption key given.
	AESBlock, AESerr := aes.NewCipher(encryptionKeySlice)
	if AESerr != nil {
		fmt.Println("error in AES")
		return
	}
	//Initialize AES-CBC
	var count int
	var initializationVector *big.Int
	for count != 16 {
		count = 0
		temp, _ := rand.Int(rand.Reader, big.NewInt(65536))
		for _, x := range temp.Bits() {
			for x != 0 {
				x &= x - 1
				count++
			}
		}
		initializationVector = temp
	}

	IVBytes := initializationVector.Bytes()
	fmt.Println(initializationVector)
	fmt.Println(IVBytes)
	//fmt.Printf("%b", initializationVector)
	firstPlainBlockBytes := messageDoublePrime[0:16]
	firstPlainBlock := new(big.Int).SetBytes(firstPlainBlockBytes)
	XORFirstBlock := new(big.Int).Xor(firstPlainBlock, initializationVector)
	XORFirstBlockSlice := XORFirstBlock.Bytes()
	//Do first round of encryption...destination of ciphertext block is encryptedSlice
	encryptedSlice := make([]byte, AESBlock.BlockSize())

	AESBlock.Encrypt(encryptedSlice, XORFirstBlockSlice)

	//Theoretically the size of info put into the XOR slice should not change
	XORSlice := make([]byte, AESBlock.BlockSize())
	copy(XORSlice, encryptedSlice)

	fmt.Printf("msgDoublePrime length mod 16: %d\n", len(messageDoublePrime) % 16)
	//Repeat previous AES-CBC procedure for rest of plaintext if needed
	for i :=16; i < len(messageDoublePrime); i += 16 {
		plainBlockBytes := messageDoublePrime[i:i+16]
		plainBlock := new(big.Int).SetBytes(plainBlockBytes)
		bigXORSlice := new(big.Int).SetBytes(XORSlice)
		XORBlock := new(big.Int).Xor(plainBlock, bigXORSlice)
		XORBlockSlice := XORBlock.Bytes()


		//fmt.Println(len(XORBlockSlice))
		AESBlock.Encrypt(XORSlice, XORBlockSlice)
		encryptedSlice = append(encryptedSlice, XORSlice...)
	}

	ciphertext := append(initializationVector.Bytes(), encryptedSlice...)
	writeToFile(os.Args[7], ciphertext)
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
	fmt.Println(decode)
	if len(decode) != 32 {
		fmt.Println("Please give 32 byte key")
		return
	}
	MACKeySlice := decode[:16]
	encryptionKeySlice := decode[16:]

	fmt.Println(MACKeySlice)
	fmt.Println(encryptionKeySlice)

	//TODO: CHECK THIS IS GOOD?!?!?!
	//encryptionKey = binary.BigEndian.Uint64(encryptionKeySlice)
	//MACKey = binary.BigEndian.Uint64(MACKeySlice)
	//fmt.Println(encryptionKey)
	//fmt.Println(MACKey)

	file, err := os.Open(os.Args[5])
	if err != nil {
		os.Exit(1)
	}
	defer file.Close()

	var lines string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = scanner.Text()
	}
	lineBytes := []byte(lines)

	if encryptMode {
		encrypt(lineBytes, MACKeySlice, encryptionKeySlice)
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
