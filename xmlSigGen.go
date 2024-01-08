package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
)

// 定义 XML 数字签名结构
type Signature struct {
	XMLName    xml.Name `xml:"Signature"`
	SignedInfo struct {
		CanonicalizationMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"CanonicalizationMethod"`
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			URI        string `xml:"URI,attr"`
			Transforms struct {
				Transform struct {
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"Transform"`
			} `xml:"Transforms"`
			DigestMethod struct {
				Algorithm string `xml:"Algorithm"`
			} `xml:"DigestMethod"`
			DigestValue string `xml:"DigestValue"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
	SignatureValue string `xml:"SignatureValue"`
}

func xmlSigGen_test() {
	// 要签名的数据
	data := "Hello, World!"

	// 读取私钥
	privateKeyPEM := []byte(`
        -----BEGIN RSA PRIVATE KEY-----
        ... (private key data here) ...
        -----END RSA PRIVATE KEY-----
    `)

	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		fmt.Println("Failed to parse private key:", err)
		//return
	}

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		return
	}

	// 计算数据的摘要
	hash := crypto.SHA1.New()
	hash.Write([]byte(data))
	digest := hash.Sum(nil)

	// 使用私钥签名数据
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest)
	if err != nil {
		fmt.Println("Failed to sign data:", err)
		return
	}

	// 编码签名为 base64
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// 创建 XML 数字签名结构
	xmlSignature := Signature{
		SignedInfo: struct {
			CanonicalizationMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"CanonicalizationMethod"`
			SignatureMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"SignatureMethod"`
			Reference struct {
				URI        string `xml:"URI,attr"`
				Transforms struct {
					Transform struct {
						Algorithm string `xml:"Algorithm,attr"`
					} `xml:"Transform"`
				} `xml:"Transforms"`
				DigestMethod struct {
					Algorithm string `xml:"Algorithm"`
				} `xml:"DigestMethod"`
				DigestValue string `xml:"DigestValue"`
			} `xml:"Reference"`
		}{
			CanonicalizationMethod: struct {
				Algorithm string `xml:"Algorithm,attr"`
			}{
				Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
			},
			SignatureMethod: struct {
				Algorithm string `xml:"Algorithm,attr"`
			}{
				Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			},
		},
		SignatureValue: signatureBase64,
	}

	// 将 XML 数字签名编码为 XML 格式
	outputXML, err := xml.MarshalIndent(xmlSignature, "", "    ")
	if err != nil {
		fmt.Println("Failed to marshal XML:", err)
		return
	}

	// 将 XML 写入文件或进行其他操作
	err = os.WriteFile("signature.xml", outputXML, 0644)
	if err != nil {
		fmt.Println("Failed to write XML file:", err)
		return
	}

	fmt.Println("XML signature created successfully.")
}

// 解析 RSA 私钥
func parsePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
