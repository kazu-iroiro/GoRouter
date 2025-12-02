package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func generateAndSaveKeys() error {
	log.Println("Generating 2048-bit RSA key pair...")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer privFile.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	log.Println("Saved: private.pem")

	pubFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer pubFile.Close()
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pem.Encode(pubFile, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubASN1})
	log.Println("Saved: public.pem")
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func serverHandshake(conn net.Conn) error {
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)
	if _, err := conn.Write(challenge); err != nil {
		return err
	}

	var sigLen uint16
	if err := binary.Read(conn, binary.BigEndian, &sigLen); err != nil {
		return err
	}

	sig := make([]byte, sigLen)
	if _, err := io.ReadFull(conn, sig); err != nil {
		return err
	}

	hashed := sha256.Sum256(challenge)
	if err := rsa.VerifyPKCS1v15(targetPubKey, crypto.SHA256, hashed[:], sig); err != nil {
		return fmt.Errorf("verify failed: %v", err)
	}
	return nil
}

func clientHandshake(conn net.Conn) error {
	buf := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	hashed := sha256.Sum256(buf)
	sig, err := rsa.SignPKCS1v15(rand.Reader, myPrivKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(len(sig))); err != nil {
		return err
	}
	_, err = conn.Write(sig)
	return err
}