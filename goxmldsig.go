package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/beevik/etree"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

func xmldsig_test() {
	// 读取私钥文件
	//privateKeyPEM, err := ioutil.ReadFile("private_key.pem")
	//if err != nil {
	//	log.Fatalf("Error reading private key file: %v", err)
	//}
	//
	//// 解析私钥
	//block, _ := pem.Decode(privateKeyPEM)
	//if block == nil {
	//	log.Fatal("Error decoding PEM block containing private key")
	//}
	//
	//privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	//if err != nil {
	//	log.Fatalf("Error parsing private key: %v", err)
	//}
	//
	//// 创建 XML 文档
	//doc := xmldsig.New()
	//doc.AddReference("",
	//	"//*[local-name(.)='Price']", // 要签名的 XML 元素
	//	sha256.New())
	//
	//// 添加签名
	//sig := xmldsig.Signature{}
	//if err := sig.Sign(doc, privateKey); err != nil {
	//	log.Fatalf("Error signing XML: %v", err)
	//}
	//
	//// 将签名添加到 XML 文档
	//doc.Signatures = append(doc.Signatures, sig)
	//
	//// 输出签名后的 XML
	//signedXML, err := doc.Bytes()
	//if err != nil {
	//	log.Fatalf("Error getting signed XML: %v", err)
	//}
	//
	//fmt.Println(string(signedXML))
	//
	//// 将签名后的 XML 保存到文件
	//err = ioutil.WriteFile("signed_xml.xml", signedXML, os.ModePerm)
	//if err != nil {
	//	log.Fatalf("Error writing signed XML to file: %v", err)
	//}
	//
	//fmt.Println("XML signature generated and saved.")
}

func chatGen() {
	// 创建一个 XML 文档
	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	data := root.CreateElement("data")
	data.SetText("Hello, XMLDSig!")

	// 创建自签名的密钥和证书
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	//serialNumber := bigIntBytes(1) // 更换此处以防止重复的序列号

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Inc"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatal(err)
	}

	// 创建证书文件
	certFile, err := os.Create("./certificate.crt")
	if err != nil {
		log.Fatalf("Failed to create certificate file: %v", err)
	}
	defer certFile.Close()

	// 写入 PEM 编码的证书数据到文件
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	err = pem.Encode(certFile, pemBlock)
	if err != nil {
		log.Fatalf("Failed to write certificate to file: %v", err)
	}

	// 从文件中读取证书数据
	certBytes, err := ioutil.ReadFile("certificate.crt")
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// 解码 PEM 编码的证书数据
	block, _ := pem.Decode(certBytes)
	if block == nil {
		log.Fatalf("Failed to decode certificate data")
	}

	// 解析 X.509 证书
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// 打印证书信息
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Subject: %s\n", certificate.Subject)
	fmt.Printf("Issuer: %s\n", certificate.Issuer)
	fmt.Printf("Not Before: %s\n", certificate.NotBefore)
	fmt.Printf("Not After: %s\n", certificate.NotAfter)
	fmt.Printf("Key Usage: %v\n", certificate.KeyUsage)
	fmt.Printf("Signature Algorithm: %s\n", certificate.SignatureAlgorithm)

	//block, _ := pem.Decode(pemBlock.Bytes)
	//if block == nil || block.Type != "CERTIFICATE" {
	//	fmt.Println("Failed to decode certificate")
	//	return
	//}
	//
	//// 使用 x509.ParseCertificate 解析证书
	//certificate, err := x509.ParseCertificate(block.Bytes)
	//if err != nil {
	//	fmt.Println("Failed to parse certificate:", err.Error())
	//	return
	//}

	// 现在 certificate 变量包含了解析后的 x509.Certificate

	// 你可以使用 certificate 中的字段，比如 Subject、Issuer、NotBefore、NotAfter 等
	fmt.Println("Subject:", certificate.Subject)
	fmt.Println("Issuer:", certificate.Issuer)
	fmt.Println("NotBefore:", certificate.NotBefore)
	fmt.Println("NotAfter:", certificate.NotAfter)

	//// 创建 XMLSigner
	//signer, err := goxmldsig.NewSigner(doc.Root())
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//// 设置私钥和证书
	//signer.SetPrivateKey(privKey)
	//signer.SetCertificate(certDER)
	//
	//// 添加对 data 元素进行签名
	//signer.AddReference("//*[local-name()='data']")
	//
	//// 签名 XML 文档
	//err = signer.Sign()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//// 获取签名后的 XML 文档
	//signedDoc := doc.WriteToString()
	//
	//// 验证签名
	//verifier, err := goxmldsig.NewVerifier(signedDoc)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//err = verifier.Verify()
	//if err != nil {
	//	log.Fatal("Signature verification failed:", err)
	//} else {
	//	fmt.Println("Signature verified successfully.")
	//}
}

func bigIntBytes(i int) []byte {
	return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}
