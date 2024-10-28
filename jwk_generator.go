package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

// Base64 URL-encode without padding
func base64UrlEncode(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

// Convert ECDSA private key to full JWK (including `x`, `y`, and `d`)
func ecdsaPrivateToJWK(privateKey *ecdsa.PrivateKey) map[string]string {
	xBytes := privateKey.PublicKey.X.Bytes()
	yBytes := privateKey.PublicKey.Y.Bytes()
	dBytes := privateKey.D.Bytes()

	return map[string]string{
		"kty": "EC",
		"crv": "P-521",
		"x":   base64UrlEncode(append(make([]byte, 66-len(xBytes)), xBytes...)),
		"y":   base64UrlEncode(append(make([]byte, 66-len(yBytes)), yBytes...)),
		"d":   base64UrlEncode(append(make([]byte, 66-len(dBytes)), dBytes...)),
	}
}

// Convert ECDSA public key to JWK (including only `x` and `y`)
func ecdsaPublicToJWK(pub *ecdsa.PublicKey) map[string]string {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	return map[string]string{
		"kty": "EC",
		"crv": "P-521",
		"x":   base64UrlEncode(append(make([]byte, 66-len(xBytes)), xBytes...)),
		"y":   base64UrlEncode(append(make([]byte, 66-len(yBytes)), yBytes...)),
	}
}

// Run an openssl command
func runOpenSSLCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	// Step 1: Generate private_key.pem
	fmt.Println("Generating private_key.pem...")
	err := runOpenSSLCommand("openssl", "ecparam", "-name", "secp521r1", "-genkey", "-noout", "-out", "private_key.pem")
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	// Step 2: Generate public_key.pem
	fmt.Println("Generating public_key.pem...")
	err = runOpenSSLCommand("openssl", "ec", "-in", "private_key.pem", "-pubout", "-out", "public_key.pem")
	if err != nil {
		log.Fatalf("Error generating public key: %v", err)
	}

	// Step 3: Load and parse the private key
	fmt.Println("Loading private_key.pem...")
	privateKeyData, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		log.Fatalf("Error reading private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatalf("Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse EC private key: %v", err)
	}

	// Step 4: Convert private key to JWK format
	fmt.Println("Converting private key to JWK...")
	privateJWK := ecdsaPrivateToJWK(privateKey)

	// Step 5: Save private key JWK to JSON file
	fmt.Println("Saving private JWK to private_key_jwk.json...")
	privateJWKJSON, err := json.MarshalIndent(privateJWK, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal private JWK to JSON: %v", err)
	}
	err = ioutil.WriteFile("private_key_jwk.json", privateJWKJSON, 0644)
	if err != nil {
		log.Fatalf("Failed to write private JWK to file: %v", err)
	}

	// Step 6: Convert public key to JWK format
	fmt.Println("Converting public key to JWK...")
	publicJWK := ecdsaPublicToJWK(&privateKey.PublicKey)

	// Step 7: Save public key JWK to JSON file
	fmt.Println("Saving public JWK to public_key_jwk.json...")
	publicJWKJSON, err := json.MarshalIndent(publicJWK, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal public JWK to JSON: %v", err)
	}
	err = ioutil.WriteFile("public_key_jwk.json", publicJWKJSON, 0644)
	if err != nil {
		log.Fatalf("Failed to write public JWK to file: %v", err)
	}

	fmt.Println("JWKs saved to private_key_jwk.json and public_key_jwk.json successfully.")
}
