package main

import (
	"bufio"
	"math"
	"math/bits"
	"strconv"
	//"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)


//RIP I was implementing sha256...Maybe will do this myself later, but for now will use golang packages to handle
func SSIG0(x string) uint {
	if nInt, err := strconv.ParseInt(x, 2, 64); err != nil {
	fmt.Println(err)
	} else {
		n := uint(nInt)
		ans := bits.RotateLeft(n, -7) ^ bits.RotateLeft(n, 18) ^ n>>3
		return ans
	}
	return -1
}

func SSIG1(x string) uint {
	if nInt, err := strconv.ParseInt(x, 2, 64); err != nil {
		fmt.Println(err)
	} else {
		n := uint(nInt)
		ans := bits.RotateLeft(n, -17) ^ bits.RotateLeft(n, 19) ^ n>>10
		return ans
	}
	return -1
}

func main() {
	//var encryptMode bool
	//var encryptionKey uint64
	//var MACKey uint64
	//var input string
	//var outFile string

	/** This section of code is to take in command line params and make sure all params are there. */
	//if len(os.Args) < 8 {
	//	fmt.Fprintln(os.Stderr, "Please give all params!")
	//	return
	//}

	/** TODO: WHEN I AM READY UNCOMMENT THIS BUSINESS!!
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
	*/
	//TODO: END OF UNCOMMENT PART!!!

	//fmt.Print(os.Args[3])

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

	msgLength := strconv.FormatInt(int64(len(lines)), 2)
	if len(msgLength) != 64 {
		n := 64 - len(msgLength)
		for i := 0 ; i < n; i++ {
			msgLength = "0" + msgLength
		}
	}

	if float64(len(lines)) < math.Exp2(64) {
		lines = lines + "1"
	}

	check := len (lines) % 512
	fmt.Printf("This is the check: %d \n", check)

	/* Logic to find K for rfc4634 memo 4.1.b. */
	if (len(lines) % 512) < 448 {
		n := 448 - (len(lines) % 512)
		for i := 0; i < n; i++ {
			lines = lines + "0"
		}
	} else if (len(lines) % 512) > 448 {
		n := 512 - ((len(lines) % 512) - 448)
		for i := 0; i < n; i++ {
			lines = lines + "0"
		}
	}
	check = len (lines) % 512
	fmt.Printf("This is the check: %d \n", check)
	lines = lines + msgLength

	check = len (lines) % 512
	fmt.Printf("This is the check: %d \n", check)

	var separatedLines []string
	var buffer string
	for i, r := range lines {
		buffer = buffer + string(r)
		if i > 0 && (i+1)%512 == 0 {
			separatedLines = append(separatedLines, buffer)
		}
	}
	fmt.Println(separatedLines)

	//calculating HMAC for each 512 bit block
	for _, block := range separatedLines {
		//Extract 32 bit words from each 512 bit block
		var words []string
		var wordBuffer string
		for i, r := range block {
			wordBuffer = wordBuffer + string(r)
			if i > 0 && (i+1)%32 == 0 {
				words = append(words, buffer)
			}
		}
	}

	fmt.Println(lines)

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
