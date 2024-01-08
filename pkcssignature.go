package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"io/ioutil"
	"log"
)

func pkcsSignature() {
	// 读取根证书
	caCertPEM, err := ioutil.ReadFile("ca_certificate.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate file: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// 读取 PKCS#7 签名
	signaturePEM, err := ioutil.ReadFile("signature.p7")
	if err != nil {
		log.Fatalf("Failed to read PKCS#7 signature file: %v", err)
	}

	p7, err := pkcs7.Parse(signaturePEM)
	if err != nil {
		log.Fatalf("Failed to parse PKCS#7 signature: %v", err)
	}

	// 创建证书池并添加根证书
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// 验证 PKCS#7 签名
	if err := p7.Verify(); err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	}

	fmt.Println("PKCS#7 signature verification succeeded.")

	// Load the PKCS#7 signature from a PEM file
	signaturePEM, err = ioutil.ReadFile("signature.pem")
	if err != nil {
		fmt.Printf("Error reading signature file: %s\n", err)
		return
	}

	// Parse the PKCS#7 signature
	block, _ := pem.Decode(signaturePEM)
	if block == nil || block.Type != "PKCS7" {
		fmt.Println("Failed to decode PKCS#7 signature")
		return
	}

	// Create a PKCS7 struct from the parsed signature
	p7, err = pkcs7.Parse(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing PKCS#7 signature: %s\n", err)
		return
	}

	// Load the certificate used for signing
	certPEM, err := ioutil.ReadFile("signing_cert.pem")
	if err != nil {
		fmt.Printf("Error reading certificate file: %s\n", err)
		return
	}

	// Parse the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fmt.Println("Failed to decode certificate")
		return
	}

	// Verify the signature using the certificate
	err = p7.Verify()
	if err != nil {
		fmt.Printf("Signature verification failed: %s\n", err)
		return
	}

	fmt.Println("Signature verification succeeded")
}
