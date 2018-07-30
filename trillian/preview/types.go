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

// Content of this file should be moved to github.com/certificate-transparency-go/types.go
// in production code.

package preview

import (
	ct "github.com/google/certificate-transparency-go"

	"github.com/google/certificate-transparency-go/tls"
)

const (
	AddPreviewChainStr ct.APIEndpoint = "add-preview-chain"
	AddComplaintStr    ct.APIEndpoint = "add-complaint"
	AddResolutionStr   ct.APIEndpoint = "add-resolution"
)

const (
	AddPreviewChainPath = "/ct/v1/add-preview-chain"
	AddComplaintPath    = "/ct/v1/add-complaint"
	AddResolutionPath   = "/ct/v1/add-resolution"
)

// LogEntryType constants. Extends the types defined in certificate-transparency-go/types.go
const (
	ComplaintLogEntryType  ct.LogEntryType = 2
	ResolutionLogEntryType ct.LogEntryType = 3
)

// ComplaintType represents the complaint reason
type ComplaintType tls.Enum // tls:"maxval:65535"

// ComplaintTyoe constants
const (
	UnknownImpersonationComplaintType ComplaintType = 0
	NameImpersonationComplaintType    ComplaintType = 1
	LogoImpersonationComplaintType    ComplaintType = 2
)

// Complaint represents a complained filed by a trusted CA
type Complaint struct {
	SerialNumber []byte              `json:"serial"`
	Reason       ComplaintType       `json:"reason"`
	Proof        [][]byte            `json:"proof"`
	Signature    tls.DigitallySigned `json:"signature"`
}

// AddComplaintRequest represents the JSON request body sent to the
// add-complaint POST method
type AddComplaintRequest struct {
	Chain     [][]byte `json:"chain"`
	Complaint `json:"content"`
}

// Resolution indicates a complaint is not true
type Resolution struct {
	ComplaintID []byte              `json:"complaintId"`
	Signature   tls.DigitallySigned `json:"signature"`
}

// AddResolutionRequest represents the JSON request body sent to the
// add-resolution POST method
type AddResolutionRequest struct {
	Chain      [][]byte `json:"chain"`
	Resolution `json:"content"`
}
