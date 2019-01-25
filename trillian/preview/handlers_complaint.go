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
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/crlsetkey"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
)

func addComplaint(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request) (int, error) {
	var err error
	method := AddComplaintName

	// Check the contents of the request and convert to slice of certificates.
	addComplaintReq, err := parseBodyAsAddComplaintRequest(li, r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to parse add-complaint body: %s", err)
	}

	_, complainerChain, err := verifyAddComplaint(li, addComplaintReq)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to verify add-complaint contents: %s", err)
	}

	// Get the current time in the form used throughout RFC6962, namely milliseconds since Unix
	// epoch, and use this throughout.
	timeMillis := uint64(li.TimeSource.Now().UnixNano() / millisPerNano)

	// Build the MerkleTreeLeaf that gets sent to the backend, and make a trillian.LogLeaf for it.
	merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addComplaintReq, timeMillis)
	if merkleLeaf == nil {
		return http.StatusBadRequest, fmt.Errorf("failed to build MerkleTreeLeaf")
	}
	extStatus, extError := addPreviewExtension(merkleLeaf, ComplaintLogEntryType)
	if extStatus != http.StatusOK {
		return extStatus, extError
	}

	leaf, err := buildLogLeafForJSONMerkleTreeLeaf(li, *merkleLeaf, 0, addComplaintReq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to build LogLeaf: %s", err)
	}
	addCrlSetKeyFromCrlSetID(&addComplaintReq.Target, &leaf)

	// Send the Merkle tree leaf on to the Log server.
	queuedLeaf, err := queueLogLeaf(li, leaf, complainerChain, r, method, ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Always use the returned leaf as the basis for an SCT.
	sct, err := generateSCT(li, queuedLeaf)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to marshall SCT: %s", err)
	}

	// We could possibly fail to issue the SCT after this but it's v. unlikely.
	li.RequestLog.IssueSCT(ctx, sctBytes)
	// The response of AddComplaintRequest is similar to AddChainRequest
	err = marshalAndWriteAddChainResponse(sct, li.signer, w)
	if err != nil {
		// reason is logged and http status is already set
		return http.StatusInternalServerError, fmt.Errorf("failed to write response: %s", err)
	}
	glog.V(3).Infof("%s: %s <= SCT", li.LogPrefix, method)
	if sct.Timestamp == timeMillis {
		lastSCTTimestamp.Set(float64(sct.Timestamp), strconv.FormatInt(li.logID, 10))
	}

	return http.StatusOK, nil
}

func addResolution(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request) (int, error) {
	var err error
	method := AddComplaintName

	// Check the contents of the request and convert to AddResolutionRequest.
	addResolutionReq, err := parseBodyAsAddResolutionRequest(li, r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to parse add-resolution body: %s", err)
	}

	chain, err := verifyAddResolution(li, addResolutionReq)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to verify add-resolution contents: %s", err)
	}

	// Get the current time in the form used throughout RFC6962, namely milliseconds since Unix
	// epoch, and use this throughout.
	timeMillis := uint64(li.TimeSource.Now().UnixNano() / millisPerNano)

	// Build the MerkleTreeLeaf that gets sent to the backend, and make a trillian.LogLeaf for it.
	merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addResolutionReq, timeMillis)
	if merkleLeaf == nil {
		return http.StatusBadRequest, fmt.Errorf("failed to build MerkleTreeLeaf")
	}
	extStatus, extError := addPreviewExtension(merkleLeaf, ResolutionLogEntryType)
	if extStatus != http.StatusOK {
		return extStatus, extError
	}

	// TODO(weihaw): non hacky solution
	// merkleLeaf.TimestampedEntry.EntryType = ResolutionLogEntryType

	leaf, err := buildLogLeafForJSONMerkleTreeLeaf(li, *merkleLeaf, 0, addResolutionReq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to build LogLeaf: %s", err)
	}
	addCrlSetKeyFromCrlSetID(&addResolutionReq.Target, &leaf)

	// Send the Merkle tree leaf on to the Log server.
	queuedLeaf, err := queueLogLeaf(li, leaf, chain, r, method, ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Always use the returned leaf as the basis for an SCT.
	sct, err := generateSCT(li, queuedLeaf)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to marshall SCT: %s", err)
	}

	// We could possibly fail to issue the SCT after this but it's v. unlikely.
	li.RequestLog.IssueSCT(ctx, sctBytes)
	// The response of AddResolutionRequest is similar to AddChainRequest
	err = marshalAndWriteAddChainResponse(sct, li.signer, w)
	if err != nil {
		// reason is logged and http status is already set
		return http.StatusInternalServerError, fmt.Errorf("failed to write response: %s", err)
	}
	glog.V(3).Infof("%s: %s <= SCT", li.LogPrefix, method)
	if sct.Timestamp == timeMillis {
		lastSCTTimestamp.Set(float64(sct.Timestamp), strconv.FormatInt(li.logID, 10))
	}

	return http.StatusOK, nil
}

func addCheckpoint(ctx context.Context, li *logInfo, w http.ResponseWriter, r *http.Request) (int, error) {
	var err error
	method := AddCheckpointName

	// Check the contents of the request and convert to AddCheckpointRequest.
	addCheckpointReq, err := parseBodyAsAddCheckpointRequest(li, r)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to parse add-checkpoint body: %s", err)
	}

	chain, err := verifyAddCheckpoint(li, addCheckpointReq)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to verify add-checkpoint contents: %s", err)
	}

	// Get the current time in the form used throughout RFC6962, namely milliseconds since Unix
	// epoch, and use this throughout.
	timeMillis := uint64(li.TimeSource.Now().UnixNano() / millisPerNano)

	// Build the MerkleTreeLeaf that gets sent to the backend, and make a trillian.LogLeaf for it.
	merkleLeaf := ct.CreateJSONMerkleTreeLeaf(addCheckpointReq, timeMillis)
	if merkleLeaf == nil {
		return http.StatusBadRequest, fmt.Errorf("failed to build MerkleTreeLeaf")
	}
	extStatus, extError := addPreviewExtension(merkleLeaf, CheckpointLogEntryType)
	if extStatus != http.StatusOK {
		return extStatus, extError
	}

	leaf, err := buildLogLeafForJSONMerkleTreeLeaf(li, *merkleLeaf, 0, addCheckpointReq)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to build LogLeaf: %s", err)
	}

	// Send the Merkle tree leaf on to the Log server.
	queuedLeaf, err := queueLogLeaf(li, leaf, chain, r, method, ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Always use the returned leaf as the basis for an SCT.
	sct, err := generateSCT(li, queuedLeaf)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to marshall SCT: %s", err)
	}

	// We could possibly fail to issue the SCT after this but it's v. unlikely.
	li.RequestLog.IssueSCT(ctx, sctBytes)
	// The response of AddCheckpointRequest is similar to AddChainRequest
	err = marshalAndWriteAddChainResponse(sct, li.signer, w)
	if err != nil {
		// reason is logged and http status is already set
		return http.StatusInternalServerError, fmt.Errorf("failed to write response: %s", err)
	}
	glog.V(3).Infof("%s: %s <= SCT", li.LogPrefix, method)
	if sct.Timestamp == timeMillis {
		lastSCTTimestamp.Set(float64(sct.Timestamp), strconv.FormatInt(li.logID, 10))
	}

	return http.StatusOK, nil
}

func queueLogLeaf(li *logInfo, leaf trillian.LogLeaf, chain []*x509.Certificate,
	r *http.Request, method EntrypointName, ctx context.Context) (*trillian.QueuedLogLeaf, error) {
	req := trillian.QueueLeavesRequest{
		LogId:    li.logID,
		Leaves:   []*trillian.LogLeaf{&leaf},
		ChargeTo: li.chargeUser(r),
	}
	if li.instanceOpts.CertificateQuotaUser != nil {
		for _, cert := range chain {
			req.ChargeTo = appendUserCharge(req.ChargeTo, li.instanceOpts.CertificateQuotaUser(cert))
		}
	}

	glog.V(2).Infof("%s: %s => grpc.QueueLeaves", li.LogPrefix, method)
	rsp, err := li.rpcClient.QueueLeaves(ctx, &req)
	glog.V(2).Infof("%s: %s <= grpc.QueueLeaves err=%v", li.LogPrefix, method, err)
	if err != nil {
		return nil, fmt.Errorf("backend QueueLeaves request failed: %s", err)
	}
	if rsp == nil {
		return nil, errors.New("missing QueueLeaves response")
	}
	if len(rsp.QueuedLeaves) != 1 {
		return nil, fmt.Errorf("unexpected QueueLeaves response leaf count: %d", len(rsp.QueuedLeaves))
	}
	return rsp.QueuedLeaves[0], nil
}

func generateSCT(li *logInfo, queuedLeaf *trillian.QueuedLogLeaf) (*ct.SignedCertificateTimestamp, error) {
	// Always use the returned leaf as the basis for an SCT.
	var loggedLeaf ct.MerkleTreeLeaf
	if rest, err := tls.Unmarshal(queuedLeaf.Leaf.LeafValue, &loggedLeaf); err != nil {
		return nil, fmt.Errorf("failed to reconstruct MerkleTreeLeaf: %s", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("extra data (%d bytes) on reconstructing MerkleTreeLeaf", len(rest))
	}

	// As the Log server has definitely got the Merkle tree leaf, we can
	// generate an SCT and respond with it.
	sct, err := buildV1SCT(li.signer, &loggedLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SCT: %s", err)
	}
	return sct, nil
}

func buildLogLeafForJSONMerkleTreeLeaf(li *logInfo,
	merkleLeaf ct.MerkleTreeLeaf, leafIndex int64, jsonData interface{}) (trillian.LogLeaf, error) {
	leafData, err := tls.Marshal(merkleLeaf)
	if err != nil {
		glog.Warningf("%s: Failed to serialize Merkle leaf: %v", li.LogPrefix, err)
		return trillian.LogLeaf{}, err
	}

	// leafIDHash allows Trillian to detect duplicate entries, so this should be
	// a hash over the cert data.
	jsonDataBytes, err := json.Marshal(jsonData)
	if err != nil {
		return trillian.LogLeaf{}, err
	}
	leafIDHash := sha256.Sum256(jsonDataBytes)

	return trillian.LogLeaf{
		LeafValue:        leafData,
		LeafIndex:        leafIndex,
		LeafIdentityHash: leafIDHash[:],
	}, nil
}

func addCrlSetKeyFromCrlSetID(id *CrlSetID, logLeaf *trillian.LogLeaf) {
	logLeaf.CrlSetKey = crlsetkey.GenerateCrlSetKeyFromRaw(id.IssuerSpkiHash, id.SerialNumber.Bytes())
}

// verifyAddComplaint is used by add-complaint. It checks whether the given
// AddComplaintRequest is valid.
func verifyAddComplaint(li *logInfo, req AddComplaintRequest) ([]*x509.Certificate, []*x509.Certificate, error) {
	var err error
	// The complainer chain that signed the complaint must origin from a trusted root CA
	complainerChain, err := ValidateChain(req.Complaint.Complainer, li.validationOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("complaint chain failed to verify: %s", err)
	}

	// The signature must be valid
	if err = verifyComplaintSignature(complainerChain[0].PublicKey, req.Complaint); err != nil {
		return nil, nil, err
	}

	// The complaint reason must be a known value
	if req.Complaint.Reason != NameImpersonationComplaintType &&
		req.Complaint.Reason != LogoImpersonationComplaintType {
		return nil, nil, fmt.Errorf("unknown complaint reason")
	}

	// The proof chain also must origin from a trusted root CA
	proofChain, verr := ValidateChain(req.Complaint.Proof, li.validationOpts)
	if verr != nil {
		return nil, nil, fmt.Errorf("proof chain failed to verify: %s", verr)
	}

	return proofChain, complainerChain, nil
}

// verifyAddResolution is used by add-resolution. It checks whether the given
// AddResolutionRequest is valid and returns the parsed certificate chain in the request.
func verifyAddResolution(li *logInfo, req AddResolutionRequest) ([]*x509.Certificate, error) {
	var err error
	// The resolver chain that signed the complaint must origin from a trusted root CA
	chain, err := ValidateChain(req.Resolution.Resolver, li.validationOpts)
	if err != nil {
		return nil, fmt.Errorf("resolution chain failed to verify: %s", err)
	}

	// The signature must be valid
	if err = verifyResolutionSignature(chain[0].PublicKey, req.Resolution); err != nil {
		return nil, err
	}

	// Since the ComplaintID is the SHA256 of the corresponding Complaint,
	// it must be 32-byte long
	if len(req.Resolution.ComplaintID) != 32 {
		return nil, fmt.Errorf("complaintID is supposed to be 32-byte long, got %d bytes", len(req.Resolution.ComplaintID))
	}
	return chain, nil
}

// verifyAddCheckpoint is used by add-resolution. It checks whether the given
// AddCheckpointRequest is valid and returns the parsed certificate chain in the request.
func verifyAddCheckpoint(li *logInfo, req AddCheckpointRequest) ([]*x509.Certificate, error) {
	var err error
	// The checkpointer chain that signed the complaint must origin from a trusted root CA
	chain, err := ValidateChain(req.Checkpoint.Checkpointer, li.validationOpts)
	if err != nil {
		return nil, fmt.Errorf("checkpoint chain failed to verify: %s", err)
	}

	// The signature must be valid
	if err = verifyCheckpointSignature(chain[0].PublicKey, req.Checkpoint); err != nil {
		return nil, err
	}

	return chain, nil
}

func verifyResolutionSignature(pubKey crypto.PublicKey, r Resolution) error {
	tbsResolution := Resolution{
		ComplaintID: r.ComplaintID,
		Reason:      r.Reason,
		Target: CrlSetID{
			IssuerSpkiHash: r.Target.IssuerSpkiHash,
			SerialNumber:   r.Target.SerialNumber,
		},
		Description: r.Description,
		Resolver:    r.Resolver,
	}
	tbsBytes, err := json.Marshal(tbsResolution)
	if err != nil {
		return fmt.Errorf("unable to verify signature: %v", err)
	}
	err = tls.VerifySignature(pubKey, tbsBytes, r.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}

func verifyComplaintSignature(pubKey crypto.PublicKey, c Complaint) error {
	tbsComplaint := Complaint{
		// SerialNumber: c.SerialNumber,
		Reason: c.Reason,
		Target: CrlSetID{
			IssuerSpkiHash: c.Target.IssuerSpkiHash,
			SerialNumber:   c.Target.SerialNumber,
		},
		Proof:      c.Proof,
		Complainer: c.Complainer,
	}
	tbsBytes, err := json.Marshal(tbsComplaint)
	if err != nil {
		return fmt.Errorf("unable to verify signature: %v", err)
	}
	err = tls.VerifySignature(pubKey, tbsBytes, c.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}

func verifyCheckpointSignature(pubKey crypto.PublicKey, r Checkpoint) error {
	tbsCheckpoint := Checkpoint{
		Timestamp:    r.Timestamp,
		StartIndex:   r.StartIndex,
		EndIndex:     r.EndIndex,
		Checkpointer: r.Checkpointer,
	}
	tbsBytes, err := json.Marshal(tbsCheckpoint)
	if err != nil {
		return fmt.Errorf("unable to verify signature: %v", err)
	}
	err = tls.VerifySignature(pubKey, tbsBytes, r.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	return nil
}

// parseBodyAsAddComplaintRequest parses the given HTTP request's body as
// a AddComplaintRequest JSON object.
func parseBodyAsAddComplaintRequest(li *logInfo, r *http.Request) (AddComplaintRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.V(1).Infof("%s: Failed to read request body: %v", li.LogPrefix, err)
		return AddComplaintRequest{}, err
	}

	var req AddComplaintRequest
	if err := json.Unmarshal(body, &req); err != nil {
		glog.V(1).Infof("%s: Failed to parse request body: %v", li.LogPrefix, err)
		return AddComplaintRequest{}, err
	}

	// The cert chain is not allowed to be empty. We'll defer other validation for later
	if len(req.Complaint.Complainer) == 0 {
		glog.V(1).Infof("%s: Request chain is empty: %s", li.LogPrefix, body)
		return AddComplaintRequest{}, errors.New("cert chain was empty")
	}

	// Do some simple checks on the complaint
	//if len(req.Complaint.SerialNumber) == 0 {
	//	glog.V(1).Infof("%s: Serial number is empty: %s", li.LogPrefix, body)
	//	return AddComplaintRequest{}, errors.New("serial number was empty")
	//}
	if len(req.Complaint.Proof) == 0 {
		glog.V(1).Infof("%s: Complaint proof is empty: %s", li.LogPrefix, body)
		return AddComplaintRequest{}, errors.New("complaint proof was empty")
	}

	return req, nil
}

// parseBodyAsAddResolutionRequest parses the given HTTP request's body as
// a AddResolutionRequest JSON object.
func parseBodyAsAddResolutionRequest(li *logInfo, r *http.Request) (AddResolutionRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.V(1).Infof("%s: Failed to read request body: %v", li.LogPrefix, err)
		return AddResolutionRequest{}, err
	}

	var req AddResolutionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		glog.V(1).Infof("%s: Failed to parse request body: %v", li.LogPrefix, err)
		return AddResolutionRequest{}, err
	}

	// The cert chain is not allowed to be empty. We'll defer other validation for later
	if len(req.Resolution.Resolver) == 0 {
		glog.V(1).Infof("%s: Request chain is empty: %s", li.LogPrefix, body)
		return AddResolutionRequest{}, errors.New("cert chain was empty")
	}

	if len(req.Resolution.ComplaintID) == 0 {
		glog.V(1).Infof("%s: ComplaintID is empty: %s", li.LogPrefix, body)
		return AddResolutionRequest{}, errors.New("complaint id was empty")
	}

	return req, nil
}

// parseBodyAsAddCheckpointRequest parses the given HTTP request's body as
// a AddCheckpointRequest JSON object.
func parseBodyAsAddCheckpointRequest(li *logInfo, r *http.Request) (AddCheckpointRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.V(1).Infof("%s: Failed to read request body: %v", li.LogPrefix, err)
		return AddCheckpointRequest{}, err
	}

	var req AddCheckpointRequest
	if err := json.Unmarshal(body, &req); err != nil {
		glog.V(1).Infof("%s: Failed to parse request body: %v", li.LogPrefix, err)
		return AddCheckpointRequest{}, err
	}

	// The cert chain is not allowed to be empty. We'll defer other validation for later
	if len(req.Checkpoint.Checkpointer) == 0 {
		glog.V(1).Infof("%s: Request chain is empty: %s", li.LogPrefix, body)
		return AddCheckpointRequest{}, errors.New("cert chain was empty")
	}

	return req, nil
}
