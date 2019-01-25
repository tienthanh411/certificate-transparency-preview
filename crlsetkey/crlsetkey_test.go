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

package crlsetkey

import (
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509util"
)

const crlSetKeyOriginal string = "dK/gl885rfmgUMk3pnZd42GwUPOh248yPJ3xfsXyBP4=-vxr+Wyeyk6o="
const crlSetKeyChainOriginal string = "dK/gl885rfmgUMk3pnZd42GwUPOh248yPJ3xfsXyBP4=-QkJCQg=="

func TestGenCrlSetKey(t *testing.T) {
	crlSet := GenerateCrlSetKeyFromAsn1(GetCertificate("testdata/test-dir.pem"))
	if crlSet != crlSetKeyOriginal {
		t.Errorf("crlSetKey %s does not match original", crlSet)
	}
	crlSetChain := GenerateCrlSetKeyFromAsn1(GetCertificate("testdata/chain.pem"))
	if crlSetChain != crlSetKeyChainOriginal {
		t.Errorf("crlSetKey %s does not match original", crlSetChain)
	}
}

func GetCertificate(filename string) []ct.ASN1Cert {
	results, error := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if error != nil {
		panic("failed to parse certificate: " + error.Error())
	}
	asn1CertChain := make([]ct.ASN1Cert, len(results))
	for i, der := range results {
		asn1CertChain[i].Data = der
	}
	return asn1CertChain
}
