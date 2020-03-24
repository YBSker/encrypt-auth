package main

import(
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

func simpleCheckSum(message []byte)

func encryptCheckSum(encryptionKey []byte, message []byte) {

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
		encryptCheckSum(lineBytes, encryptionKeySlice)
	} else {
		decryptCheckSum(lineBytes, encryptionKeySlice)
	}
}