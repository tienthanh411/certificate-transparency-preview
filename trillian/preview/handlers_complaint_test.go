// Copyright 2016 Google Inc. All Rights Reserved.
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

package preview

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/trillian"
	trillianCrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"

	cttestonly "github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
)

func TestAddResolution(t *testing.T) {
	var err error
	// valid proof chain that is originated from a trusted CA
	leaf2CertPEM := readFile(t, "../testdata/leaf02.cert")
	intCertPEM := readFile(t, "../testdata/int-ca.cert")
	rootCertPEM := readFile(t, "../testdata/fake-ca.cert")

	// Identifies the signer, but otherwise is passive payload.
	trustedCAChainPEM := []string{
		intCertPEM,
		rootCertPEM,
	}
	untrustedCAChainPEM := []string{
		cttestonly.FakeIntermediateCertPEM,
		cttestonly.FakeCACertPEM,
	}
	targetChainPEM := []string{
		leaf2CertPEM,
		intCertPEM,
		rootCertPEM,
	}

	// private keys
	trustedCAPrivKeyPEM := readFile(t, "../testdata/int-ca.privkey.pem")
	trustedCAKeyPassword := "babelfish"

	untrustedCAPrivKeyPEM := readFile(t, "../testdata/ct-http-server.privkey.pem")
	untrustedCAKeyPassword := "dirk"

	validResolution := createResolution(t, make([]byte, 32), trustedCAPrivKeyPEM, trustedCAKeyPassword,
		trustedCAChainPEM, targetChainPEM)
	invalidComplaintIDResolution := createResolution(t, []byte{1}, trustedCAPrivKeyPEM, trustedCAKeyPassword,
		trustedCAChainPEM, targetChainPEM)
	untrustedResolution := createResolution(t, make([]byte, 32), untrustedCAPrivKeyPEM, untrustedCAKeyPassword,
		untrustedCAChainPEM, targetChainPEM)
	invalidSignatureResolution := Resolution{
		ComplaintID: make([]byte, 32),
		Signature: tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
			Signature: []byte{1, 2, 3},
		},
	}

	var tests = []struct {
		descr           string
		chain           []string
		resolution      Resolution
		toSign          bool
		want            int
		err             error
		remoteQuotaUser string
		enableCertQuota bool
		// if remote quota enabled, it must be the first entry here
		wantQuotaUsers []string
	}{
		{
			descr:      "success",
			chain:      []string{intCertPEM, rootCertPEM},
			resolution: validResolution,
			toSign:     true,
			want:       http.StatusOK,
		},
		{
			descr:      "success without root",
			chain:      []string{intCertPEM},
			resolution: validResolution,
			toSign:     true,
			want:       http.StatusOK,
		},
		{
			descr:      "invalid complaint ID",
			chain:      []string{intCertPEM, rootCertPEM},
			resolution: invalidComplaintIDResolution,
			toSign:     false,
			want:       http.StatusBadRequest,
		},
		{
			descr:      "signed by untrusted CA",
			chain:      []string{intCertPEM, rootCertPEM},
			resolution: untrustedResolution,
			toSign:     false,
			want:       http.StatusBadRequest,
		},
		{
			descr:      "invalid signature",
			chain:      []string{intCertPEM, rootCertPEM},
			resolution: invalidSignatureResolution,
			toSign:     false,
			want:       http.StatusBadRequest,
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{rootCertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		info.setRemoteQuotaUser(test.remoteQuotaUser)
		info.enableCertQuota(test.enableCertQuota)
		pool := loadCertsIntoPoolOrDie(t, test.chain)
		reqBody, addResolutionReq := createJSONAddResolutionRequest(t, *pool, test.resolution)

		if test.toSign {
			merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addResolutionReq, fakeTimeMillis)
			if merkleLeaf == nil {
				t.Errorf("Failed to create Merkle tree leaf")
				continue
			}
			extStatus, _ := addPreviewExtension(merkleLeaf, ResolutionLogEntryType)
			if extStatus != http.StatusOK {
				t.Errorf("Failed to create preview extension")
				continue
			}
			leafChain := pool.RawCertificates()
			root := info.roots.RawCertificates()[0]
			if !leafChain[len(leafChain)-1].Equal(root) {
				// The submitted chain may not include a root, but the generated LogLeaf will
				fullChain := make([]*x509.Certificate, len(leafChain)+1)
				copy(fullChain, leafChain)
				fullChain[len(leafChain)] = root
				leafChain = fullChain
			}
			leaves := logLeavesForJSONData(t, addResolutionReq, merkleLeaf)
			queuedLeaves := make([]*trillian.QueuedLogLeaf, len(leaves))
			for i, leaf := range leaves {
				addCrlSetKeyFromCrlSetID(&addResolutionReq.Target, leaf)
				queuedLeaves[i] = &trillian.QueuedLogLeaf{
					Leaf:   leaf,
					Status: status.New(codes.OK, "ok").Proto(),
				}
			}
			rsp := trillian.QueueLeavesResponse{QueuedLeaves: queuedLeaves}
			req := &trillian.QueueLeavesRequest{LogId: 0x42, Leaves: leaves}
			if len(test.wantQuotaUsers) > 0 {
				req.ChargeTo = &trillian.ChargeTo{User: test.wantQuotaUsers}
			}
			info.client.EXPECT().QueueLeaves(deadlineMatcher(), req).Return(&rsp, test.err)
		}

		recorder := makeAddResolutionRequest(t, info.li, reqBody)
		if recorder.Code != test.want {
			t.Errorf("addChain(%s)=%d (body:%v); want %dv", test.descr, recorder.Code, recorder.Body, test.want)
			continue
		}
		if test.want == http.StatusOK {
			var resp ct.AddChainResponse
			if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
				t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
			}

			if got, want := ct.Version(resp.SCTVersion), ct.V1; got != want {
				t.Errorf("resp.SCTVersion=%v; want %v", got, want)
			}
			if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
				t.Errorf("resp.ID=%v; want %v", got, want)
			}
			if got, want := resp.Timestamp, uint64(1469185273000); got != want {
				t.Errorf("resp.Timestamp=%d; want %d", got, want)
			}
			if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
				t.Errorf("resp.Signature=%s; want %s", got, want)
			}
		}
	}
}

func TestAddComplaint(t *testing.T) {
	var err error
	// valid proof chain that is originated from a trusted CA
	leafCertPEM := readFile(t, "../testdata/leaf01.cert")
	leaf2CertPEM := readFile(t, "../testdata/leaf02.cert")
	intCertPEM := readFile(t, "../testdata/int-ca.cert")
	rootCertPEM := readFile(t, "../testdata/fake-ca.cert")
	validProofChainPEM := []string{
		leafCertPEM,
		intCertPEM,
		rootCertPEM,
	}
	targetChainPEM := []string{
		leaf2CertPEM,
		intCertPEM,
		rootCertPEM,
	}

	// invalid proof chain that is not originated from a trusted CA
	invalidProofChainPEM := []string{
		cttestonly.LeafSignedByFakeIntermediateCertPEM,
		cttestonly.FakeIntermediateCertPEM,
		cttestonly.FakeCACertPEM,
	}

	// Identifies the signer, but otherwise is passive payload.
	trustedCAChainPEM := []string{
		intCertPEM,
		rootCertPEM,
	}
	untrustedCAChainPEM := []string{
		cttestonly.FakeIntermediateCertPEM,
		cttestonly.FakeCACertPEM,
	}

	// private keys
	trustedCAPrivKeyPEM := readFile(t, "../testdata/int-ca.privkey.pem")
	trustedCAKeyPassword := "babelfish"

	untrustedCAPrivKeyPEM := readFile(t, "../testdata/ct-http-server.privkey.pem")
	untrustedCAKeyPassword := "dirk"

	validComplaint := createComplaint(t, NameImpersonationComplaintType, validProofChainPEM,
		big.NewInt(12345), trustedCAPrivKeyPEM, trustedCAKeyPassword, trustedCAChainPEM,
		targetChainPEM)
	unknownReasonComplaint := createComplaint(t, UnknownImpersonationComplaintType, validProofChainPEM,
		big.NewInt(12345), trustedCAPrivKeyPEM, trustedCAKeyPassword, trustedCAChainPEM,
		targetChainPEM)
	untrustedComplaint := createComplaint(t, NameImpersonationComplaintType, validProofChainPEM,
		big.NewInt(12345), untrustedCAPrivKeyPEM, untrustedCAKeyPassword, untrustedCAChainPEM,
		targetChainPEM)
	invalidSignatureComplaint := Complaint{
		Reason: validComplaint.Reason,
		// SerialNumber: validComplaint.SerialNumber,
		Proof: validComplaint.Proof,
		Signature: tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
			Signature: []byte{1, 2, 3},
		},
	}
	untrustedProofComplaint := createComplaint(t, NameImpersonationComplaintType, invalidProofChainPEM,
		big.NewInt(12345), trustedCAPrivKeyPEM, trustedCAKeyPassword, untrustedCAChainPEM,
		targetChainPEM)

	var tests = []struct {
		descr           string
		chain           []string
		complaint       Complaint
		toSign          bool
		want            int
		err             error
		remoteQuotaUser string
		enableCertQuota bool
		// if remote quota enabled, it must be the first entry here
		wantQuotaUsers []string
	}{
		{
			descr:     "success",
			chain:     []string{intCertPEM, rootCertPEM},
			complaint: validComplaint,
			toSign:    true,
			want:      http.StatusOK,
		},
		{
			descr:     "success without root",
			chain:     []string{intCertPEM},
			complaint: validComplaint,
			toSign:    true,
			want:      http.StatusOK,
		},
		{
			descr:     "unknown complaint reason",
			chain:     []string{intCertPEM, rootCertPEM},
			complaint: unknownReasonComplaint,
			toSign:    false,
			want:      http.StatusBadRequest,
		},
		{
			descr:     "signed by untrusted CA",
			chain:     []string{intCertPEM, rootCertPEM},
			complaint: untrustedComplaint,
			toSign:    false,
			want:      http.StatusBadRequest,
		},
		{
			descr:     "invalid signature",
			chain:     []string{intCertPEM, rootCertPEM},
			complaint: invalidSignatureComplaint,
			toSign:    false,
			want:      http.StatusBadRequest,
		},
		{
			descr:     "proof chain not originated from a trusted CA",
			chain:     []string{intCertPEM, rootCertPEM},
			complaint: untrustedProofComplaint,
			toSign:    false,
			want:      http.StatusBadRequest,
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{rootCertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		info.setRemoteQuotaUser(test.remoteQuotaUser)
		info.enableCertQuota(test.enableCertQuota)
		pool := loadCertsIntoPoolOrDie(t, test.chain)
		reqBody, addComplaintReq := createJSONAddComplaintRequest(t, *pool, test.complaint)

		if test.toSign {
			merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addComplaintReq, fakeTimeMillis)
			if merkleLeaf == nil {
				t.Errorf("Failed to create Merkle tree leaf")
				continue
			}
			extStatus, _ := addPreviewExtension(merkleLeaf, ComplaintLogEntryType)
			if extStatus != http.StatusOK {
				t.Errorf("Failed to create preview extension")
				continue
			}
			leafChain := pool.RawCertificates()
			root := info.roots.RawCertificates()[0]
			if !leafChain[len(leafChain)-1].Equal(root) {
				// The submitted chain may not include a root, but the generated LogLeaf will
				fullChain := make([]*x509.Certificate, len(leafChain)+1)
				copy(fullChain, leafChain)
				fullChain[len(leafChain)] = root
				leafChain = fullChain
			}
			leaves := logLeavesForJSONData(t, addComplaintReq, merkleLeaf)
			queuedLeaves := make([]*trillian.QueuedLogLeaf, len(leaves))
			for i, leaf := range leaves {
				addCrlSetKeyFromCrlSetID(&addComplaintReq.Target, leaf)
				queuedLeaves[i] = &trillian.QueuedLogLeaf{
					Leaf:   leaf,
					Status: status.New(codes.OK, "ok").Proto(),
				}
			}
			rsp := trillian.QueueLeavesResponse{QueuedLeaves: queuedLeaves}
			req := &trillian.QueueLeavesRequest{LogId: 0x42, Leaves: leaves}
			if len(test.wantQuotaUsers) > 0 {
				req.ChargeTo = &trillian.ChargeTo{User: test.wantQuotaUsers}
			}
			info.client.EXPECT().QueueLeaves(deadlineMatcher(), req).Return(&rsp, test.err)
		}

		recorder := makeAddComplaintRequest(t, info.li, reqBody)
		if recorder.Code != test.want {
			t.Errorf("addChain(%s)=%d (body:%v); want %dv", test.descr, recorder.Code, recorder.Body, test.want)
			continue
		}
		if test.want == http.StatusOK {
			var resp ct.AddChainResponse
			if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
				t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
			}

			if got, want := ct.Version(resp.SCTVersion), ct.V1; got != want {
				t.Errorf("resp.SCTVersion=%v; want %v", got, want)
			}
			if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
				t.Errorf("resp.ID=%v; want %v", got, want)
			}
			if got, want := resp.Timestamp, uint64(1469185273000); got != want {
				t.Errorf("resp.Timestamp=%d; want %d", got, want)
			}
			if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
				t.Errorf("resp.Signature=%s; want %s", got, want)
			}
		}
	}
}

func TestAddCheckpoint(t *testing.T) {
	var err error
	// valid proof chain that is originated from a trusted CA
	intCertPEM := readFile(t, "../testdata/int-ca.cert")
	rootCertPEM := readFile(t, "../testdata/fake-ca.cert")
	var timestamp uint64 = 1000
	var startIndex int64 = 1
	var endIndex int64 = 2

	// Identifies the signer, but otherwise is passive payload.
	trustedCAChainPEM := []string{
		intCertPEM,
		rootCertPEM,
	}
	untrustedCAChainPEM := []string{
		cttestonly.FakeIntermediateCertPEM,
		cttestonly.FakeCACertPEM,
	}

	// private keys
	trustedCAPrivKeyPEM := readFile(t, "../testdata/int-ca.privkey.pem")
	trustedCAKeyPassword := "babelfish"

	untrustedCAPrivKeyPEM := readFile(t, "../testdata/ct-http-server.privkey.pem")
	untrustedCAKeyPassword := "dirk"

	validCheckpoint := createCheckpoint(t, timestamp, startIndex, endIndex, trustedCAPrivKeyPEM, trustedCAKeyPassword, trustedCAChainPEM)
	untrustedCheckpoint := createCheckpoint(t, timestamp, startIndex, endIndex, untrustedCAPrivKeyPEM, untrustedCAKeyPassword, untrustedCAChainPEM)
	invalidSignatureCheckpoint := Checkpoint{
		Signature: tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
			Signature: []byte{1, 2, 3},
		},
	}

	var tests = []struct {
		descr           string
		chain           []string
		checkpoint      Checkpoint
		toSign          bool
		want            int
		err             error
		remoteQuotaUser string
		enableCertQuota bool
		// if remote quota enabled, it must be the first entry here
		wantQuotaUsers []string
	}{
		{
			descr:      "success",
			chain:      []string{intCertPEM, rootCertPEM},
			checkpoint: validCheckpoint,
			toSign:     true,
			want:       http.StatusOK,
		},
		{
			descr:      "success without root",
			chain:      []string{intCertPEM},
			checkpoint: validCheckpoint,
			toSign:     true,
			want:       http.StatusOK,
		},
		{
			descr:      "signed by untrusted CA",
			chain:      []string{intCertPEM, rootCertPEM},
			checkpoint: untrustedCheckpoint,
			toSign:     false,
			want:       http.StatusBadRequest,
		},
		{
			descr:      "invalid signature",
			chain:      []string{intCertPEM, rootCertPEM},
			checkpoint: invalidSignatureCheckpoint,
			toSign:     false,
			want:       http.StatusBadRequest,
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{rootCertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		info.setRemoteQuotaUser(test.remoteQuotaUser)
		info.enableCertQuota(test.enableCertQuota)
		pool := loadCertsIntoPoolOrDie(t, test.chain)
		reqBody, addCheckpointReq := createJSONAddCheckpointRequest(t, *pool, test.checkpoint)

		if test.toSign {
			merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addCheckpointReq, fakeTimeMillis)
			if merkleLeaf == nil {
				t.Errorf("Failed to create Merkle tree leaf")
				continue
			}
			extStatus, _ := addPreviewExtension(merkleLeaf, CheckpointLogEntryType)
			if extStatus != http.StatusOK {
				t.Errorf("Failed to create preview extension")
				continue
			}
			leafChain := pool.RawCertificates()
			root := info.roots.RawCertificates()[0]
			if !leafChain[len(leafChain)-1].Equal(root) {
				// The submitted chain may not include a root, but the generated LogLeaf will
				fullChain := make([]*x509.Certificate, len(leafChain)+1)
				copy(fullChain, leafChain)
				fullChain[len(leafChain)] = root
				leafChain = fullChain
			}
			leaves := logLeavesForJSONData(t, addCheckpointReq, merkleLeaf)
			queuedLeaves := make([]*trillian.QueuedLogLeaf, len(leaves))
			for i, leaf := range leaves {
				queuedLeaves[i] = &trillian.QueuedLogLeaf{
					Leaf:   leaf,
					Status: status.New(codes.OK, "ok").Proto(),
				}
			}
			rsp := trillian.QueueLeavesResponse{QueuedLeaves: queuedLeaves}
			req := &trillian.QueueLeavesRequest{LogId: 0x42, Leaves: leaves}
			if len(test.wantQuotaUsers) > 0 {
				req.ChargeTo = &trillian.ChargeTo{User: test.wantQuotaUsers}
			}
			info.client.EXPECT().QueueLeaves(deadlineMatcher(), req).Return(&rsp, test.err)
		}

		recorder := makeAddCheckpointRequest(t, info.li, reqBody)
		if recorder.Code != test.want {
			t.Errorf("addChain(%s)=%d (body:%v); want %dv", test.descr, recorder.Code, recorder.Body, test.want)
			continue
		}
		if test.want == http.StatusOK {
			var resp ct.AddChainResponse
			if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
				t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
			}

			if got, want := ct.Version(resp.SCTVersion), ct.V1; got != want {
				t.Errorf("resp.SCTVersion=%v; want %v", got, want)
			}
			if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
				t.Errorf("resp.ID=%v; want %v", got, want)
			}
			if got, want := resp.Timestamp, uint64(1469185273000); got != want {
				t.Errorf("resp.Timestamp=%d; want %d", got, want)
			}
			if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
				t.Errorf("resp.Signature=%s; want %s", got, want)
			}
		}
	}
}

func createComplaint(t *testing.T, reason ComplaintType, proofChainPEM []string,
	serial *big.Int, signerPrivKeyPEM string, keyPassword string,
	complainerChainPEM []string, targetChainPEM []string) Complaint {
	var err error

	proofChainBytes := make([][]byte, len(proofChainPEM))
	pool := loadCertsIntoPoolOrDie(t, proofChainPEM)
	for i, proofRawCert := range pool.RawCertificates() {
		proofChainBytes[i] = proofRawCert.Raw
	}

	complainerChainBytes := make([][]byte, len(complainerChainPEM))
	complainerPool := loadCertsIntoPoolOrDie(t, complainerChainPEM)
	for i, complainerRawCert := range complainerPool.RawCertificates() {
		complainerChainBytes[i] = complainerRawCert.Raw
	}

	targetChainBytes := make([][]byte, len(targetChainPEM))
	targetCert := make([]*x509.Certificate, len(targetChainPEM))
	targetPool := loadCertsIntoPoolOrDie(t, targetChainPEM)
	for i, targetRawCert := range targetPool.RawCertificates() {
		targetChainBytes[i] = targetRawCert.Raw
		targetCert[i], _ = x509.ParseCertificate(targetRawCert.Raw)
	}

	// sign the complaint
	issuerHash := sha256.Sum256(targetCert[1].RawSubjectPublicKeyInfo)
	complaint := Complaint{
		Reason: reason,
		Target: CrlSetID{
			IssuerSpkiHash: issuerHash[:],
			SerialNumber:   targetCert[0].SerialNumber,
		},
		Proof:      proofChainBytes,
		Complainer: complainerChainBytes,
	}
	tbsBytes, err := json.Marshal(complaint)
	if err != nil {
		t.Fatalf("Failed to serialize complaint data: %v", err)
	}

	signerKey, err := pem.UnmarshalPrivateKey(signerPrivKeyPEM, keyPassword)
	if err != nil {
		t.Fatalf("Failed to unmarshal signer key: %v", err)
	}
	signer := trillianCrypto.NewSigner(0, signerKey, crypto.SHA256)
	signature, err := signer.Sign(tbsBytes)
	if err != nil {
		t.Fatalf("Failed to signed the complaint: %v", err)
	}

	digitallySigned := tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}

	complaint.Signature = digitallySigned
	return complaint
}

func createResolution(t *testing.T, complaintID []byte,
	signerPrivKeyPEM string, keyPassword string,
	resolverChainPEM []string, targetChainPEM []string) Resolution {

	resolverChainBytes := make([][]byte, len(resolverChainPEM))
	resolverPool := loadCertsIntoPoolOrDie(t, resolverChainPEM)
	for i, resolverRawCert := range resolverPool.RawCertificates() {
		resolverChainBytes[i] = resolverRawCert.Raw
	}

	targetChainBytes := make([][]byte, len(targetChainPEM))
	targetCert := make([]*x509.Certificate, len(targetChainPEM))
	targetPool := loadCertsIntoPoolOrDie(t, targetChainPEM)
	for i, targetRawCert := range targetPool.RawCertificates() {
		targetChainBytes[i] = targetRawCert.Raw
		targetCert[i], _ = x509.ParseCertificate(targetRawCert.Raw)
	}

	// sign the complaint
	issuerHash := sha256.Sum256(targetCert[1].RawSubjectPublicKeyInfo)
	resolution := Resolution{
		ComplaintID: complaintID,
		Target: CrlSetID{
			IssuerSpkiHash: issuerHash[:],
			SerialNumber:   targetCert[0].SerialNumber,
		},
		Resolver: resolverChainBytes,
	}
	tbsBytes, err := json.Marshal(resolution)
	if err != nil {
		t.Fatalf("Failed to serialize resolution data: %v", err)
	}

	signerKey, err := pem.UnmarshalPrivateKey(signerPrivKeyPEM, keyPassword)
	if err != nil {
		t.Fatalf("Failed to unmarshal signer key: %v", err)
	}
	signer := trillianCrypto.NewSigner(0, signerKey, crypto.SHA256)
	signature, err := signer.Sign(tbsBytes)
	if err != nil {
		t.Fatalf("Failed to signed the resolution: %v", err)
	}

	digitallySigned := tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}

	resolution.Signature = digitallySigned
	return resolution
}

func createCheckpoint(t *testing.T, timestamp uint64,
	startIndex int64, endIndex int64,
	signerPrivKeyPEM string, keyPassword string,
	checkpointerChainPEM []string) Checkpoint {

	checkpointerChainBytes := make([][]byte, len(checkpointerChainPEM))
	checkpointerPool := loadCertsIntoPoolOrDie(t, checkpointerChainPEM)
	for i, checkpointerRawCert := range checkpointerPool.RawCertificates() {
		checkpointerChainBytes[i] = checkpointerRawCert.Raw
	}

	checkpoint := Checkpoint{
		Timestamp:    timestamp,
		StartIndex:   startIndex,
		EndIndex:     endIndex,
		Checkpointer: checkpointerChainBytes,
	}
	tbsBytes, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatalf("Failed to serialize checkpoint data: %v", err)
	}

	signerKey, err := pem.UnmarshalPrivateKey(signerPrivKeyPEM, keyPassword)
	if err != nil {
		t.Fatalf("Failed to unmarshal signer key: %v", err)
	}
	signer := trillianCrypto.NewSigner(0, signerKey, crypto.SHA256)
	signature, err := signer.Sign(tbsBytes)
	if err != nil {
		t.Fatalf("Failed to signed the checkpoint: %v", err)
	}

	digitallySigned := tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}

	checkpoint.Signature = digitallySigned
	return checkpoint
}

func readFile(t *testing.T, filepath string) string {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read file %s :%v", filepath, err)
	}
	return string(content)
}

func logLeavesForJSONData(t *testing.T, jsonData interface{}, merkleLeaf *ct.MerkleTreeLeaf) []*trillian.LogLeaf {
	t.Helper()
	leafData, err := tls.Marshal(*merkleLeaf)
	if err != nil {
		t.Fatalf("failed to serialize leaf: %v", err)
	}

	jsonDataBytes, err := json.Marshal(jsonData)
	if err != nil {
		t.Fatalf("failed to serialize JSON data: %v", err)
	}
	leafIDHash := sha256.Sum256(jsonDataBytes)

	return []*trillian.LogLeaf{{LeafIdentityHash: leafIDHash[:], LeafValue: leafData}}
}

func makeAddComplaintRequest(t *testing.T, li *logInfo, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler := AppHandler{Info: li, Handler: addComplaint, Name: "AddComplaint", Method: http.MethodPost}
	return makeAddChainRequestInternal(t, handler, "add-complaint", body)
}

func makeAddResolutionRequest(t *testing.T, li *logInfo, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler := AppHandler{Info: li, Handler: addResolution, Name: "AddResolution", Method: http.MethodPost}
	return makeAddChainRequestInternal(t, handler, "add-resolution", body)
}

func makeAddCheckpointRequest(t *testing.T, li *logInfo, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler := AppHandler{Info: li, Handler: addCheckpoint, Name: "AddCheckpoint", Method: http.MethodPost}
	return makeAddChainRequestInternal(t, handler, "add-resolution", body)
}

func createJSONAddComplaintRequest(t *testing.T, p PEMCertPool, complaint Complaint) (io.Reader, AddComplaintRequest) {
	t.Helper()
	var req AddComplaintRequest
	for _, rawCert := range p.RawCertificates() {
		req.Complainer = append(req.Complainer, rawCert.Raw)
	}
	req.Complaint = complaint

	var buffer bytes.Buffer
	// It's tempting to avoid creating and flushing the intermediate writer but it doesn't work
	writer := bufio.NewWriter(&buffer)
	err := json.NewEncoder(writer).Encode(&req)
	writer.Flush()

	if err != nil {
		t.Fatalf("Failed to create test json: %v", err)
	}

	return bufio.NewReader(&buffer), req
}

func createJSONAddResolutionRequest(t *testing.T, p PEMCertPool, resolution Resolution) (io.Reader, AddResolutionRequest) {
	t.Helper()
	var req AddResolutionRequest
	for _, rawCert := range p.RawCertificates() {
		req.Resolver = append(req.Resolver, rawCert.Raw)
	}
	req.Resolution = resolution

	var buffer bytes.Buffer
	// It's tempting to avoid creating and flushing the intermediate writer but it doesn't work
	writer := bufio.NewWriter(&buffer)
	err := json.NewEncoder(writer).Encode(&req)
	writer.Flush()

	if err != nil {
		t.Fatalf("Failed to create test json: %v", err)
	}

	return bufio.NewReader(&buffer), req
}

func createJSONAddCheckpointRequest(t *testing.T, p PEMCertPool, checkpoint Checkpoint) (io.Reader, AddCheckpointRequest) {
	t.Helper()
	var req AddCheckpointRequest
	for _, rawCert := range p.RawCertificates() {
		req.Checkpointer = append(req.Checkpointer, rawCert.Raw)
	}
	req.Checkpoint = checkpoint

	var buffer bytes.Buffer
	// It's tempting to avoid creating and flushing the intermediate writer but it doesn't work
	writer := bufio.NewWriter(&buffer)
	err := json.NewEncoder(writer).Encode(&req)
	writer.Flush()

	if err != nil {
		t.Fatalf("Failed to create test json: %v", err)
	}

	return bufio.NewReader(&buffer), req
}
