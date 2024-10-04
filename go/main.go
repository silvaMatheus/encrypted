package main

import (
    "crypto"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "strings"
    "golang.org/x/crypto/pbkdf2"
)

func main() {
    messageBytes, err := ioutil.ReadFile("../assets/message.txt")
    if err != nil {
        fmt.Println("Error reading message.txt:", err)
        return
    }
    message := string(messageBytes)

    parts := strings.Split(message, ".")
    if len(parts) != 3 {
        fmt.Println("Invalid message format")
        return
    }
    encryptedPassphraseB64 := parts[0]
    encryptedPayloadB64 := parts[1]
    signatureB64 := parts[2]

    encryptedPassphrase, err := base64.StdEncoding.DecodeString(encryptedPassphraseB64)
    if err != nil {
        fmt.Println("Error decoding encrypted passphrase:", err)
        return
    }
    encryptedPayload, _ := base64.StdEncoding.DecodeString(encryptedPayloadB64)
    signature, _ := base64.StdEncoding.DecodeString(signatureB64)

    privateKey, err := loadPrivateKey("../assets/Private.pem")
    if err != nil {
        fmt.Println("Error loading private key:", err)
        return
    }

    passphrase, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedPassphrase)
    if err != nil {
        fmt.Println("Error decrypting passphrase:", err)
        return
    }

    publicKeyBytes, _ := ioutil.ReadFile("../assets/Public.pub")
    blockPub, _ := pem.Decode(publicKeyBytes)
    publicKeyInterface, _ := x509.ParsePKIXPublicKey(blockPub.Bytes)
    publicKey := publicKeyInterface.(*rsa.PublicKey)

    hashed := sha256.Sum256(encryptedPassphrase)
    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
    if err != nil {
        fmt.Println("Signature verification failed:", err)
        return
    }

    salt := encryptedPayload[8:16]
    payloadData := encryptedPayload[16:]

  
    keyIV := pbkdf2.Key(passphrase, salt, 10000, 48, sha256.New)
    key := keyIV[:32]
    iv := keyIV[32:48]


    blockCipher, _ := aes.NewCipher(key)

    mode := cipher.NewCBCDecrypter(blockCipher, iv)
    decrypted := make([]byte, len(payloadData))
    mode.CryptBlocks(decrypted, payloadData)

    decrypted = pkcs7Unpad(decrypted)

    fmt.Println("Decrypted message:", string(decrypted))
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
    privateKeyBytes, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(privateKeyBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }

    var privateKey *rsa.PrivateKey

    if block.Type == "RSA PRIVATE KEY" {
       
        privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
        if err != nil {
            return nil, err
        }
    } else if block.Type == "PRIVATE KEY" {
    
        key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
        if err != nil {
            return nil, err
        }
        var ok bool
        privateKey, ok = key.(*rsa.PrivateKey)
        if !ok {
            return nil, fmt.Errorf("not an RSA private key")
        }
    } else {
        return nil, fmt.Errorf("unknown private key type: %s", block.Type)
    }

    return privateKey, nil
}

func pkcs7Unpad(data []byte) []byte {
    length := len(data)
    paddingLen := int(data[length-1])
    return data[:length-paddingLen]
}
