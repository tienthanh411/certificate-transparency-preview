// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Utility to generate a certificate string key based on CrlSet.  The key
// is meant to distinguish different unique certificate chains, but be
// fast and easily used.  It is structured as:
// "<spki-hash-base64>-<serial-number-base64>" where the spki-hash is from
// the SPKI hash of the intermediate CA certificate, and the serial-number
// from the entity certificate.  Both values are in base64 representation.
package crlsetkey

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	ct "github.com/google/certificate-transparency-go"
	ctX509 "github.com/google/certificate-transparency-go/x509"
)

func GenerateCrlSetKeyFromAsn1(asn1CertChain []ct.ASN1Cert) string {
	x509CertChain := make([]*x509.Certificate, len(asn1CertChain))
	for i, cert := range asn1CertChain {
		var err error
		x509CertChain[i], err = x509.ParseCertificate(cert.Data)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
	}
	return GenerateCrlSetKeyFromX509(x509CertChain)
}

func GenerateCrlSetKeyFromX509(x509CertChain []*x509.Certificate) string {
	switch len(x509CertChain) {
	case 0:
		return "-"
	case 1:
		return GenerateCrlSetKeyFromRaw(x509CertChain[0].RawSubjectPublicKeyInfo,
			x509CertChain[0].SerialNumber.Bytes())
	default:
		return GenerateCrlSetKeyFromRaw(x509CertChain[0].RawSubjectPublicKeyInfo,
			x509CertChain[1].SerialNumber.Bytes())
	}
}

func GenerateCrlSetKeyFromChain(chain []*ctX509.Certificate) string {
	switch len(chain) {
	case 0:
		return "-"
	case 1:
		return GenerateCrlSetKeyFromRaw(chain[0].RawSubjectPublicKeyInfo,
			chain[0].SerialNumber.Bytes())
	default:
		return GenerateCrlSetKeyFromRaw(chain[0].RawSubjectPublicKeyInfo,
			chain[1].SerialNumber.Bytes())
	}
}

// Generate the CrlSet identifier from spkiHash and serialNumber.
func GenerateCrlSetKeyFromRaw(spki []byte, serialNumber []byte) string {
	h := sha256.New()
	h.Write(spki)
	spkiHash := h.Sum(nil)
	return GenerateCrlSetKeyString(spkiHash, serialNumber)
}

// Generate the CrlSet identifier from spkiHash and serialNumber.
func GenerateCrlSetKeyString(spkiHash []byte, serialNumber []byte) string {
	// Unlike other keying methods, this does not truncate spkiHash
	// or serial-number.  This also doesn't attempt to spread out the
	// entries as this tries to keep the key strings easy to interpret.
	var buffer bytes.Buffer
	buffer.WriteString(base64.StdEncoding.EncodeToString(spkiHash))
	buffer.WriteString("-")
	buffer.WriteString(base64.StdEncoding.EncodeToString(serialNumber))
	return buffer.String()
}
