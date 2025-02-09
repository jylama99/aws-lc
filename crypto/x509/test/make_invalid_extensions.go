/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// make_invalid_extensions.go generates a number of certificate chains with
// invalid extension encodings.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type extension struct {
	// The name of the extension, in a form suitable for including in a
	// filename.
	name string
	// The extension's OID.
	oid []int
}

var extensions = []extension{
	{name: "authority_key_identifier", oid: []int{2, 5, 29, 35}},
	{name: "basic_constraints", oid: []int{2, 5, 29, 19}},
	{name: "ext_key_usage", oid: []int{2, 5, 29, 37}},
	{name: "key_usage", oid: []int{2, 5, 29, 15}},
	{name: "name_constraints", oid: []int{2, 5, 29, 30}},
	{name: "subject_alt_name", oid: []int{2, 5, 29, 17}},
	{name: "subject_key_identifier", oid: []int{2, 5, 29, 14}},
}

var leafKey, intermediateKey, rootKey *ecdsa.PrivateKey

func init() {
	leafKey = ecdsaKeyFromPEMOrPanic(leafKeyPEM)
	intermediateKey = ecdsaKeyFromPEMOrPanic(intermediateKeyPEM)
	rootKey = ecdsaKeyFromPEMOrPanic(rootKeyPEM)
}

type templateAndKey struct {
	template x509.Certificate
	key      *ecdsa.PrivateKey
}

func generateCertificateOrPanic(path string, subject, issuer *templateAndKey) {
	cert, err := x509.CreateCertificate(rand.Reader, &subject.template, &issuer.template, &subject.key.PublicKey, issuer.key)
	if err != nil {
		panic(err)
	}
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		panic(err)
	}
}

func main() {
	notBefore, err := time.Parse(time.RFC3339, "2000-01-01T00:00:00Z")
	if err != nil {
		panic(err)
	}
	notAfter, err := time.Parse(time.RFC3339, "2100-01-01T00:00:00Z")
	if err != nil {
		panic(err)
	}

	root := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(1),
			Subject:               pkix.Name{CommonName: "Invalid Extensions Root"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		},
		key: rootKey,
	}
	intermediate := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(2),
			Subject:               pkix.Name{CommonName: "Invalid Extensions Intermediate"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		},
		key: intermediateKey,
	}
	leaf := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(3),
			Subject:               pkix.Name{CommonName: "www.example.com"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  false,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
			DNSNames:              []string{"www.example.com"},
		},
		key: leafKey,
	}

	// Generate a valid certificate chain from the templates.
	generateCertificateOrPanic("invalid_extension_root.pem", &root, &root)
	generateCertificateOrPanic("invalid_extension_intermediate.pem", &intermediate, &root)
	generateCertificateOrPanic("invalid_extension_leaf.pem", &leaf, &intermediate)

	// Make copies of each of the three certificates with invalid extensions.
	// These copies may be substituted into the valid chain.
	for _, ext := range extensions {
		invalidExtension := []pkix.Extension{{Id: ext.oid, Value: []byte("INVALID")}}

		rootInvalid := root
		rootInvalid.template.ExtraExtensions = invalidExtension
		generateCertificateOrPanic(fmt.Sprintf("invalid_extension_root_%s.pem", ext.name), &rootInvalid, &rootInvalid)

		intermediateInvalid := intermediate
		intermediateInvalid.template.ExtraExtensions = invalidExtension
		generateCertificateOrPanic(fmt.Sprintf("invalid_extension_intermediate_%s.pem", ext.name), &intermediateInvalid, &root)

		leafInvalid := leaf
		leafInvalid.template.ExtraExtensions = invalidExtension
		generateCertificateOrPanic(fmt.Sprintf("invalid_extension_leaf_%s.pem", ext.name), &leafInvalid, &intermediate)
	}
}

const leafKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoPUXNXuH9mgiS/nk
024SYxryxMa3CyGJldiHymLxSquhRANCAASRKti8VW2Rkma+Kt9jQkMNitlCs0l5
w8u3SSwm7HZREvmcBCJBjVIREacRqI0umhzR2V5NLzBBP9yPD/A+Ch5X
-----END PRIVATE KEY-----`

const intermediateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWHKCKgY058ahE3t6
vpxVQgzlycgCVMogwjK0y3XMNfWhRANCAATiOnyojN4xS5C8gJ/PHL5cOEsMbsoE
Y6KT9xRQSh8lEL4d1Vb36kqUgkpqedEImo0Og4Owk6VWVVR/m4Lk+yUw
-----END PRIVATE KEY-----`

const rootKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwND/eHytW0I417J
Hr+qcPlp5N1jM3ACXys57bPujg+hRANCAAQmdqXYl1GvY7y3jcTTK6MVXIQr44Tq
ChRYI6IeV9tIB6jIsOY+Qol1bk8x/7A5FGOnUWFVLEAPEPSJwPndjolt
-----END PRIVATE KEY-----`

func ecdsaKeyFromPEMOrPanic(in string) *ecdsa.PrivateKey {
	keyBlock, _ := pem.Decode([]byte(in))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		panic("could not decode private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(*ecdsa.PrivateKey)
}
