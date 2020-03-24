package main
import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

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
	} else if len(lineBytes) < 32 {
		fmt.Println("Not enough information provided")
		os.Exit(0)
	}

	var decodedTextBytes []byte

	//testIVProcess := make([]byte, 16)
	fmt.Println(lineBytes)
	chunkCount := 0
}