package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)

// PurchaseOrder 结构体，用于解析和生成 XML
type PurchaseOrder struct {
	XMLName xml.Name `xml:"PurchaseOrder"`
	Item    Item     `xml:"Item"`
	Buyer   Buyer    `xml:"Buyer"`
	// 添加签名字段
	Signature string `xml:"Signature"`
}

type Item struct {
	Number      string  `xml:"number,attr"`
	Description string  `xml:"Description"`
	Price       float64 `xml:"Price"`
}

type Buyer struct {
	ID      string  `xml:"id,attr"`
	Name    string  `xml:"Name"`
	Address Address `xml:"Address"`
}

type Address struct {
	Street     string `xml:"Street"`
	Town       string `xml:"Town"`
	State      string `xml:"State"`
	Country    string `xml:"Country"`
	PostalCode string `xml:"PostalCode"`
}

func xmlSigEncap_test() {
	// 创建 XML 数据
	po := PurchaseOrder{
		Item: Item{
			Number:      "130046593231",
			Description: "Video Game",
			Price:       10.29,
		},
		Buyer: Buyer{
			ID:   "8492340",
			Name: "My Name",
			Address: Address{
				Street:     "One Network Drive",
				Town:       "Burlington",
				State:      "MA",
				Country:    "United States",
				PostalCode: "01803",
			},
		},
	}

	// 计算 XML 数据的摘要
	xmlData, _ := xml.Marshal(po)
	hashed := sha256.Sum256(xmlData)

	// 使用私钥对摘要进行数字签名
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		return
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	// 将数字签名添加到 XML 中
	signatureHex := fmt.Sprintf("%x", signature)
	po.Signature = signatureHex

	// 将带有数字签名的 XML 数据写入文件
	xmlWithSignature, _ := xml.MarshalIndent(po, "", "  ")
	err = ioutil.WriteFile("signed_purchase_order.xml", xmlWithSignature, os.ModePerm)
	if err != nil {
		fmt.Println("Error writing XML file:", err)
		return
	}

	fmt.Println("XML with signature generated and saved.")
}
