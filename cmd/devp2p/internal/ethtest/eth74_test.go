// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package ethtest

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestDecodeEth74Header(t *testing.T) {
	proofHash := crypto.Keccak256Hash([]byte("proof"))
	fields := make([]any, headerDependencyProofHash+1)
	for i := range fields {
		fields[i] = uint64(0)
	}
	fields[headerNumber] = uint64(7)
	fields[headerGasLimit] = uint64(60_000_000)
	fields[headerTimestamp] = uint64(1_800_000_000)
	fields[headerSlotNumber] = uint64(9)
	fields[headerDependencyProofHash] = proofHash
	raw, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	h, err := decodeEth74Header(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.hash != crypto.Keccak256Hash(raw) || h.number != 7 || h.gasLimit != 60_000_000 || h.time != 1_800_000_000 || h.slot != 9 {
		t.Errorf("decoded %+v", h)
	}
	if h.proofHash == nil || *h.proofHash != proofHash {
		t.Errorf("dependency_proof_hash %v, want %v", h.proofHash, proofHash)
	}

	if raw, err = rlp.EncodeToBytes(fields[:headerDependencyProofHash]); err != nil {
		t.Fatal(err)
	}
	if h, err = decodeEth74Header(raw); err != nil {
		t.Fatal(err)
	}
	if h.proofHash != nil {
		t.Error("header without the field has a dependency_proof_hash")
	}
}

func TestCheckDependencyProofs(t *testing.T) {
	proof := []byte("proof")
	proofHash := crypto.Keccak256Hash(proof)
	withProof := &eth74Header{number: 3, proofHash: &proofHash, built: true}
	noDeps := &eth74Header{number: 2, proofHash: &emptyProofHash, built: true}
	preFork := &eth74Header{number: 0}
	notHeld := &eth74Header{number: 1, proofHash: &proofHash}

	tests := []struct {
		name    string
		headers []*eth74Header
		proofs  [][]byte
		valid   bool
	}{
		{"matching proof", []*eth74Header{withProof}, [][]byte{proof}, true},
		{"no dependencies", []*eth74Header{noDeps}, [][]byte{{}}, true},
		{"pre-fork", []*eth74Header{preFork}, [][]byte{{}}, true},
		{"unknown", []*eth74Header{nil}, [][]byte{{}}, true},
		{"unavailable", []*eth74Header{notHeld}, [][]byte{{}}, true},
		{"mismatching proof", []*eth74Header{withProof}, [][]byte{[]byte("other")}, false},
		{"proof for no dependencies", []*eth74Header{noDeps}, [][]byte{proof}, false},
		{"proof for pre-fork", []*eth74Header{preFork}, [][]byte{proof}, false},
		{"proof for unknown", []*eth74Header{nil}, [][]byte{proof}, false},
		{"built block unavailable", []*eth74Header{withProof}, [][]byte{{}}, false},
		{"too few entries", []*eth74Header{nil, nil}, [][]byte{{}}, false},
		{"too many entries", []*eth74Header{nil}, [][]byte{{}, {}}, false},
	}
	for _, test := range tests {
		err := checkDependencyProofs(test.headers, &dependencyProofsPacket{Proofs: test.proofs})
		if (err == nil) != test.valid {
			t.Errorf("%s: got error %v, want valid %v", test.name, err, test.valid)
		}
	}
}
