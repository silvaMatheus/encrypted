# Decryption Challenge - Solution

## Overview

This repository contains my solution to the decryption challenge proposed by Fufild. The challenge involved working with an encrypted message provided by a third-party partner, divided into three parts. The objective was to decrypt the message, verify its integrity, and recover a hidden flag.

I chose to implement the solution in **Go** to explore what it would be like to develop in this language. It was an interesting and fun experience.

## Project Structure

- **go/**
  - `main.go`
  - `go.mod`
  - `go.sum`
- **assets/**
  - `message.txt`
  - `Private.pem`
  - `Public.pub`
- **node/**
  - `verify_passphrase.js`
  - `decrypt.js`

## Prerequisites

- **Go**: Make sure you have Go installed on your machine. You can download it from [https://golang.org/dl/](https://golang.org/dl/).
- **Node.js**: Required to run JavaScript scripts. Download from [https://nodejs.org/](https://nodejs.org/).

## Dependencies

The program uses the following libraries:

- **Go Standard Libraries**:
  - `crypto/rsa`, `crypto/x509`, `crypto/sha256`, `crypto/aes`, `crypto/cipher`
- **External Libraries**:
  - `golang.org/x/crypto/pbkdf2`: For key derivation using PBKDF2.

## Setup Instructions

1. **Clone the Repository**

   ```bash
   git clone https://github.com/silvaMatheus/encrypted.git
   ```

2. **Install Dependencies**

   For Go:

   ```bash
   cd go
   go mod download
   ```

   For Node.js:

   ```bash
   cd node
   npm install
   ```

## How to Use

1. **Run with Go**

   ```bash
   cd go
   go run main.go
   ```

2. **Run with Node.js**

   ```bash
   node decrypt.js
   ```
