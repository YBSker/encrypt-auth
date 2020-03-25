package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func stringifyCheckSum(x []byte) string {
	var stringData string
	for _, n := range x {
		str := strconv.FormatUint(uint64(n), 2)
		for len(str) != 8 {
			str = "0" + str
		}
		stringData += str
	}
	return stringData
}

func simpleAttackCheckSum(message []byte) byte {
	checkSum := 0
	for i, _ := range message {
		checkSum += int(message[i])
	}
	return byte(checkSum % 256)
}

func sanitizeCheckSum(s string) string {
	out := strings.TrimSpace(string(s))
	out = strings.Replace(out, " ", "", -1)
	return out
}

func getCheckSumOutput(initVecNum []byte, cipherText []byte) string {
	//initVecBytes := make ([]byte, 16)
	testVec := initVecNum
	//binary.BigEndian.PutUint64(initVecBytes, testVec)
	testCipher := make([]byte, len(cipherText))
	copy(testCipher, cipherText)
	testBlock := append(testVec, testCipher...)
	//fmt.Println("THIS IS TESTBLOCK")
	//fmt.Println(testBlock)

	err := ioutil.WriteFile("checksumDecryptAttempt.txt", []byte(stringifyCheckSum(testBlock)), 0644)
	if err != nil {
		fmt.Println("Error in file write.")
	}
	testCmd := exec.Command("decrypt-chk-test", "-i", os.Args[2])	//testCmd.Run()
	output, _ := testCmd.Output()
	//fmt.Println(string(output))
	return sanitizeCheckSum(string(output))

}

func main() {
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
	if len(lineBytes) == 0 {
		fmt.Println("Empty Ciphertext")
		os.Exit(0)
	} else if len(lineBytes) < 16 {
		fmt.Println("Not enough information provided")
		os.Exit(0)
	}

	initializationVector := lineBytes[:16]
	//initVecNum := binary.LittleEndian.Uint64(initializationVector)
	initVecUse := 0
	originalCipherText := make([]byte, len(lineBytes[16:]))
	copy(originalCipherText, lineBytes[16:])

	var plainTextBytes []byte

	//testCipher := make([]byte, 1)
	var testCipher []byte
	//fmt.Println(initializationVector)
	//fmt.Println(lineBytes)
	for i := 0; i < len(lineBytes) - 16; i++ {
		//Ensure that we do the CTR thing for every 8 bytes
		//if initVecUse == 16 {
		//	initVecNum++
		//}
		testCipher = append(testCipher, lineBytes[i])
		//Force a 0 tag!

		//Test for a ciphertext byte that will cause preEnc XOR CT =0
		for j := 0; j < 256; j++ {
			testCipher[i] = byte(j)
			//testCipher[0] = simpleAttackCheckSum(testCipher[1:])
			//	fmt.Println(testCipher[i])
			//getCheckSumOutput(initializationVector, testCipher)
			if getCheckSumOutput(initializationVector, testCipher) != "INVALIDCHECKSUM" {
				break
			}
		}
		//Plaintext found by XORing testCipher byte and original ciphertext byte
		if i != 0 {
			plainByte := testCipher[i] ^ originalCipherText[i]
			//fmt.Println( testCipher[i])
			//fmt.Println(originalCipherText[i])
			plainTextBytes = append(plainTextBytes, plainByte)
		}
		initVecUse++
	}
	//fmt.Println(initVecUse)

	//fmt.Println(plainTextBytes)

	//Check that our proposed plainText is correct
	err = ioutil.WriteFile("checksumDecryptAttempt.txt", []byte(stringifyCheckSum(plainTextBytes)), 0644)
	//err = ioutil.WriteFile("checksumDecryptAttempt.txt", []byte("01100100"), 0644)
	if err != nil {
		fmt.Println("Error in file write.")
	}
	testCmd := exec.Command("decrypt-chk-test", "-i", os.Args[2])	//testCmd.Run()
	output, _ := testCmd.Output()
	//fmt.Println(output)
	//fmt.Println(stringifyCheckSum(output))

	if string(output) == "SUCCESS" {
		fmt.Println(stringifyCheckSum(plainTextBytes))
		//fmt.Println("Successful attack!")
	} else {
		//fmt.Println(stringifyCheckSum(plainTextBytes))
		fmt.Println("FAILURE!!!")
	}

	//testIVProcess := make([]byte, 16)
	//fmt.Println(lineBytes)
}