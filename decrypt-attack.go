package main

import (
	//"crypto/rand"
	"fmt"
	"io/ioutil"
	//"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func stringify(x []byte) string {
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

func sanitize(s string) string {
	out := strings.TrimSpace(string(s))
	out = strings.Replace(out, " ", "", -1)
	return out
}

func getTestOutput(cipherTextBlock []byte, XORTextBlock []byte) string {
	//testBlock := new(big.Int).Xor(new(big.Int).SetBytes(cipherTextBlock), new(big.Int).SetBytes(XORTextBlock)).Bytes()
	testBlock := append(XORTextBlock, cipherTextBlock...)
	//fmt.Println(stringify(testBlock))
	//Test if the new byte value at end of 16 byte block is a valid padding...
	err := ioutil.WriteFile("decrypt-attack-out.txt", []byte(stringify(testBlock)), 0644)
	if err != nil {
		fmt.Println("Error in file write.")
	}
	testCmd := exec.Command("decrypt-test", "-i", os.Args[2])	//testCmd.Run()
	output, _ := testCmd.Output()
	//fmt.Println(string(output))
	return sanitize(string(output))
}

func testPurePadding(cipherTextBlock []byte, XORTextBlock []byte) bool {
	if getTestOutput(cipherTextBlock, XORTextBlock) != "INVALIDPADDING" {
		testOnThis := make([]byte, len(XORTextBlock))
		copy(testOnThis, XORTextBlock)
		testOnThis[0] = byte(30)
		if getTestOutput(cipherTextBlock, testOnThis) == "INVALIDPADDING" {
			return true
		}
	}
	return false
}

func main() {
	//TODO: REMOVE THIS AND THE NEXT (well modify the cmd line to get rid of ans)
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
	} else if len(lineBytes) < 32 {
		fmt.Println("Not enough information provided")
		os.Exit(0)
	}

	var decodedTextBytes []byte

	//testIVProcess := make([]byte, 16)
	//fmt.Println(lineBytes)
	//chunkCount := 0
	//var endPlace int

	for i := 16; i < len(lineBytes); i += 16 {
		//fmt.Printf("We are in place: %d\n", i)
		testIV := lineBytes[i-16 : i]

		originalIV := make([]byte, 16)
		copy(originalIV, testIV)
		cipherTextBlock := lineBytes[i : i+16]
		decodedTextBlock := make([]byte, 16)

		currentPlace := 0
		for currentPlace < 16 {
			//If we do not have a block that is all "16" byte 16 times (valid padding)...
			//fmt.Println("Im inside after purePaddingTest")
			for k, _ := range testIV {
				placeTestIV := make([]byte, len(testIV))
				copy(placeTestIV, testIV)
				placeTestIV[k] = byte(255)
				output := getTestOutput(cipherTextBlock, placeTestIV)
				//fmt.Println(output)
				//fmt.Println(k)
				//fmt.Println(currentPlace)
				if output == "INVALIDPADDING" && currentPlace != 0 {
					currentPlace = len(cipherTextBlock) - k
					break
				}
			}

			if currentPlace >= 16 {
				break
			}

			// Change everything after currentplace to currentplace + 1
			for l := 0; l < currentPlace; l++ {
				//fmt.Println(currentPlace)
				XORIntermediary := byte(currentPlace) ^ byte(currentPlace+1)
				//fmt.Println("THIS IS THE XORINTERMEDIARYTHINGY")
				//fmt.Println(XORIntermediary)
				//fmt.Println(testIV[len(testIV)-1-l])
				if l != 15 {
					testIV[len(testIV)-1-l] =
						testIV[len(testIV)-1-l] ^ XORIntermediary
				}
			}
			//Iterate through all possible byte vals of a single byte

			for j := 0; j < 256; j++ {
				testIV[len(testIV)-1-currentPlace] = byte(j)
				//fmt.Println(testIV[len(testIV)-1])
				//fmt.Println(byte(j))
				output := getTestOutput(cipherTextBlock, testIV)
				//fmt.Println(output)
				//if output != "INVALIDPADDING" {
				//	rightValues = append(rightValues, byte(j))
				//
				//}

				//if output == "" || output == "1" || output == "2" || output == "3" || output == "4" {
				//	break
				//}
				//
				if output != "INVALIDPADDING" {
					//endPlace = len(testIV)-1-currentPlace
					break
				}
			}
			for j := 0; j < 256; j++ {
				testIV[0] = byte(j)
				output := getTestOutput(cipherTextBlock, testIV)
				if output != "INVALIDPADDING" {
					//endPlace = len(testIV)-1-currentPlace
					break
				}
			}
			//copy(testIVProcess, testIV)
			//fmt.Println(testIV)
			if currentPlace == 0 {
				currentPlace++
			}

			//fmt.Println(currentPlace)
		}
		//for x := 1; x < 16; x++{
		//	testIV[x] = testIV[x] ^ 15 ^ 16
		//}

		//fmt.Println(testIV)
		//decrypt the first element since that's buggy for some reason...



		if !testPurePadding(cipherTextBlock, originalIV) {
			for m, _ := range testIV {
				//if m == 0 {
				//	decodedTextBlock[m] = (testIV[m] ^ originalIV[m])
				//} else {
				//	decodedTextBlock[m] = 16 ^ (testIV[m] ^ originalIV[m])
				//}
				decodedTextBlock[m] = 16 ^ (testIV[m] ^ originalIV[m])

			}
			//fmt.Println(testIV)
			//fmt.Println(originalIV)
			//fmt.Println(decodedTextBlock)
			//fmt.Println("I'm in the not pure padding!")
			decodedTextBytes = append(decodedTextBytes, decodedTextBlock...)
			//fmt.Println(decodedTextBytes)
		} else {
			for q := 0; q < 16; q++ {
				decodedTextBytes = append(decodedTextBytes, byte(16))
			}
		}
		//chunkCount++
	}
	//fmt.Println(decodedTextBytes)


	////First let's try to decrypt 16 bytes...
	//var testBlock []byte
	////generate random 1-15
	//for i:=0; i < 15; i++ {
	//	temp, _ := rand.Int(rand.Reader, big.NewInt(256))
	//	testBlock = append(testBlock, temp.Bytes()...)
	//}
	////generate 16

	//Does feeding in the right value give us a confirm?
	//TODO: DELETE THIS LINE AND MODIFY THE NEXT
	//hardANs := "01110111 01100101 01100001 01110010 01100101 01110100 01101000 01100101 01100011 01101000 01100001 01101101 01101001 01110000 01101111"
	//TODO: UNCOMMENT THIS LINE WHEN DONE
	//fmt.Println("01110111 01100101 01100001 01110010 01100101 01110100 01101000 01100101 01100011 01101000 01100001 01101101 01101001 01110000 01101111")

	n := decodedTextBytes[len(decodedTextBytes)-1]
	messagePrime := decodedTextBytes[:len(decodedTextBytes)-int(n)]
	plainText := messagePrime[:len(messagePrime)-32]

	ans := stringify(plainText)
	//fmt.Println(ans)
	err = ioutil.WriteFile("decrypt-attack-out.txt", []byte(stringify(plainText)), 0644)
	if err != nil {
		fmt.Println("Error in file write.")
	}
	cmd := exec.Command("decrypt-test", "-i", os.Args[2])
	output, _ := cmd.Output()
	if err != nil {
		fmt.Println("Issue with getting output of test exec")
		os.Exit(0)
	}
	out := strings.TrimSpace(string(output))
	out = strings.Replace(out, " ", "", -1)

	var stringAns []byte
	for i := 0; i < len(ans); i += 8 {
		n, _ := strconv.ParseUint(ans[i:i+8], 2, 8)
		stringAns = append(stringAns, byte(n))
	}

	if out == "SUCCESS" {
		fmt.Println(string(stringAns))
	} else {
		//fmt.Println(string(stringAns))
		fmt.Println("FAILURE!")
	}

}
