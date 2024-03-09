package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func readHiddenInput(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println() // Print a new line after the hidden input
	return bytePassword, nil
}

func encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Create a new GCM cipher using the given key
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the data using AES-GCM
	encryptedData := aesGCM.Seal(nil, nonce, data, nil)

	// Combine the nonce and the encrypted data
	ciphertext := append(nonce, encryptedData...)

	// Convert the result to a hexadecimal string
	return hex.EncodeToString(ciphertext), nil
}

func decrypt(encryptedString string, key []byte) ([]byte, error) {
	// Decode the hexadecimal string
	ciphertext, err := hex.DecodeString(encryptedString)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the ciphertext
	nonceSize := 12
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Create a new GCM cipher using the given key
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the data using AES-GCM
	decryptedData, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func main() {

	// Prompt for operation (encrypt or decrypt)
	fmt.Print("Enter 'e' to encrypt or 'd' to decrypt: ")
	operationInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading operation:", err)
		return
	}
	operation := strings.TrimSpace(operationInput)

	// Read key from the prompt (hidden)
	key, err := readHiddenInput("Enter the encryption key (16, 24, or 32 bytes): ")
	if err != nil {
		fmt.Println("Error reading key:", err)
		return
	}

	// Read data from the prompt
	fmt.Print("Enter the data: ")
	dataInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading data:", err)
		return
	}
	dataInput = strings.TrimSpace(dataInput)
	data := []byte(dataInput)

	var result string

	switch operation {
	case "e":
		// Encrypt the data
		result, err = encrypt(data, key)
		if err != nil {
			fmt.Println("Encryption error:", err)
			return
		}
	case "d":
		// Decrypt the data
		resultBytes, err := decrypt(string(data), key)
		if err != nil {
			fmt.Println("Decryption error:", err)
			return
		}
		result = string(resultBytes)
	default:
		fmt.Println("Invalid operation. Please enter 'e' to encrypt or 'd' to decrypt.")
		return
	}

	fmt.Println("Result:", result)
}
