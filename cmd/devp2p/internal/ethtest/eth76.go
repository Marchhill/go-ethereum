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
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/utesting"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// eth/76 (EIP-8518) extends eth/74 with aggregate proof wrappers [transactions, deps,
// recursive-stark], coverage hints, transaction-hash manifests and compact retrieval.
// go-ethereum does not implement it, so its messages are defined here.

const (
	eth76 = 76

	getProofWrapperManifests76Msg = 0x1b
	proofWrapperManifests76Msg    = 0x1c

	maxAnnounced76 = 64
	maxRequested76 = 32

	// noPenaltyWindow is how long a test waits for a disconnection that must not come.
	noPenaltyWindow = 3 * time.Second
)

// wrapperAnnouncement76 is a NewProofWrapperHashes entry [length, hash, deps-hash, txs-hash].
type wrapperAnnouncement76 struct {
	Length   uint64
	Hash     common.Hash
	DepsHash common.Hash
	TxsHash  common.Hash
}

type getProofWrappersPacket76 struct {
	RequestId uint64
	Compact   uint64
	Hashes    []common.Hash
}

type servedWrapper76 struct {
	Hash    common.Hash
	Wrapper rlp.RawValue
}

type proofWrappersPacket76 struct {
	RequestId uint64
	Wrappers  []servedWrapper76
}

type getManifestsPacket76 struct {
	RequestId uint64
	Hashes    []common.Hash
}

type servedManifest76 struct {
	Hash     common.Hash
	TxHashes []common.Hash
}

type manifestsPacket76 struct {
	RequestId uint64
	Manifests []servedManifest76
}

// wrapperFixture76 is an EIP-8518 wrapper of one frame transaction with a leanSPHINCS
// claim and a secp256k1 claim, whose recursive-stark is a 3-byte stand-in that verifies
// under no verifier. The node can decode it and match its transaction claims against its
// dependencies, but must reject its proof. Generated with Nethermind's ProofWrapperCodec.
type wrapperFixture76 struct {
	wrapper      []byte
	hash         common.Hash
	txHash       common.Hash // the consensus hash of the wrapper's one transaction
	depsHash     common.Hash
	txsHash      common.Hash
	encodingHash common.Hash
}

var wrapperFixtures76 = []wrapperFixture76{
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e018094b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a01f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a691118080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b86000000000000000000000000000000000000000000000000000000000000000101f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a6911103783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x89bb3372d4a887f3f7723db8a0c246f1e5b93c71197b174653102b1da53ce13c"),
		txHash:  common.HexToHash("0x85f357866216b49b043ea73f19edbde26514b22b1ebeae0c154dc3d57e9812b3"),
	},
}

// Eth76Tests returns the eth/76 (EIP-8518) proof wrapper tests. The node must aggregate its
// mempool on a chain with EIP-8288 active, such as the genesis in testdata/eip8512. Each
// test passes without checking anything if the node does not offer eth/76.
func (s *Suite) Eth76Tests() []utesting.Test {
	return []utesting.Test{
		{Name: "Eth76Status", Fn: s.TestEth76Status},
		{Name: "ServeUnannouncedWrappers", Fn: s.TestServeUnannouncedWrappers},
		{Name: "ServeUnannouncedManifests", Fn: s.TestServeUnannouncedManifests},
		{Name: "FetchAnnouncedWrapper", Fn: s.TestFetchAnnouncedWrapper},
		{Name: "InvalidProofNoPenalty", Fn: s.TestInvalidProofNoPenalty},
		{Name: "FalseHintDisconnects", Fn: s.TestFalseHintDisconnects},
		{Name: "UnrequestedWrapperDisconnects", Fn: s.TestUnrequestedWrapperDisconnects},
		{Name: "EmptyResponseNoPenalty", Fn: s.TestEmptyResponseNoPenalty},
		{Name: "CompactCacheMissRetriesFull", Fn: s.TestCompactCacheMissRetriesFull},
		{Name: "ReferenceInFullResponseDisconnects", Fn: s.TestReferenceInFullResponseDisconnects},
		{Name: "MalformedAnnouncementDisconnects", Fn: s.TestMalformedAnnouncementDisconnects},
	}
}

func (s *Suite) TestEth76Status(t *utesting.T) {
	t.Log(`This test offers eth/76 and checks that the node negotiates it and completes the
status exchange on it.`)
	if conn := s.dialEth76(t); conn != nil {
		conn.Close()
	}
}

func (s *Suite) TestServeUnannouncedWrappers(t *utesting.T) {
	t.Log(`This test requests wrappers the node never announced. It must treat them as
unavailable and answer empty, echoing the request id, without disconnecting.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	if err := conn.checkAlive76(); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestServeUnannouncedManifests(t *utesting.T) {
	t.Log(`This test requests the manifests of wrappers the node never announced. It must
answer empty, echoing the request id.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	id := randomRequestID()
	if err := conn.Write(ethProto, getProofWrapperManifests76Msg, &getManifestsPacket76{RequestId: id, Hashes: []common.Hash{randomHash()}}); err != nil {
		t.Fatal(err)
	}
	data, err := conn.readEthMsg(proofWrapperManifests76Msg, time.Now().Add(timeout))
	if err != nil {
		t.Fatalf("no ProofWrapperManifests response: %v", err)
	}
	var resp manifestsPacket76
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		t.Fatalf("invalid ProofWrapperManifests: %v", err)
	}
	if resp.RequestId != id || len(resp.Manifests) != 0 {
		t.Fatalf("response %d with %d manifests, want %d with none", resp.RequestId, len(resp.Manifests), id)
	}
}

func (s *Suite) TestFetchAnnouncedWrapper(t *utesting.T) {
	t.Log(`This test announces a wrapper. The node must request it with GetProofWrappers,
naming its hash among at most 32 distinct hashes, with compact 0 or 1.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	if !slices.Contains(req.Hashes, f.hash) {
		t.Fatalf("node requested %v, not the announced %v", req.Hashes, f.hash)
	}
}

func (s *Suite) TestInvalidProofNoPenalty(t *utesting.T) {
	t.Log(`This test serves an announced wrapper whose hints and claims match but whose proof
does not verify. The node must discard it without penalizing the peer, and must not
fetch it again when it is announced again.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	if err := conn.serveWrappers76(req, func(common.Hash) []byte { return f.wrapper }); err != nil {
		t.Fatal(err)
	}
	if err := conn.checkAlive76(); err != nil {
		t.Fatalf("node penalized a proof failure: %v", err)
	}
	if err := conn.announce76(f.announcement()); err != nil {
		t.Fatal(err)
	}
	if data, err := conn.readEthMsg(getProofWrappersMsg, time.Now().Add(noPenaltyWindow)); err == nil {
		var again getProofWrappersPacket76
		if rlp.DecodeBytes(data, &again) == nil && slices.Contains(again.Hashes, f.hash) {
			t.Fatal("node fetched a wrapper it already discarded")
		}
	}
}

func (s *Suite) TestFalseHintDisconnects(t *utesting.T) {
	t.Log(`This test announces a wrapper with a false deps-hash and serves the real wrapper.
The mismatch must make the node disconnect, before and regardless of proof validity.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	ann := f.announcement()
	ann.DepsHash = randomHash()
	req := conn.announceAndAwaitRequest76(t, ann)
	if err := conn.serveWrappers76(req, func(common.Hash) []byte { return f.wrapper }); err != nil {
		t.Fatal(err)
	}
	if err := conn.expectDisconnect76(); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestUnrequestedWrapperDisconnects(t *utesting.T) {
	t.Log(`This test answers the node's wrapper request with an entry for a hash it did not
request. An unmatched response must make the node disconnect.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	resp := &proofWrappersPacket76{RequestId: req.RequestId, Wrappers: []servedWrapper76{{Hash: randomHash(), Wrapper: f.wrapper}}}
	if err := conn.Write(ethProto, proofWrappersMsg, resp); err != nil {
		t.Fatal(err)
	}
	if err := conn.expectDisconnect76(); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestEmptyResponseNoPenalty(t *utesting.T) {
	t.Log(`This test answers the node's wrapper request with an empty response, as a peer
whose serving budget is spent does. The node must not penalize it.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	if err := conn.Write(ethProto, proofWrappersMsg, &proofWrappersPacket76{RequestId: req.RequestId}); err != nil {
		t.Fatal(err)
	}
	if err := conn.checkAlive76(); err != nil {
		t.Fatalf("node penalized an empty response: %v", err)
	}
}

func (s *Suite) TestCompactCacheMissRetriesFull(t *utesting.T) {
	t.Log(`This test answers a compact wrapper request with a reference to a transaction
encoding the node cannot hold. The node must discard it without penalty and retry with
compact 0 and a fresh request id.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	if req.Compact != 1 {
		t.Logf("node requested in full, so it cannot miss its cache; skipping")
		return
	}
	if err := conn.serveWrappers76(req, func(common.Hash) []byte { return f.compact(t) }); err != nil {
		t.Fatal(err)
	}
	retry := conn.awaitRequest76(t)
	if retry.Compact != 0 || retry.RequestId == req.RequestId || !slices.Contains(retry.Hashes, f.hash) {
		t.Fatalf("retry %d compact %d for %v, want a fresh id, compact 0 and %v", retry.RequestId, retry.Compact, retry.Hashes, f.hash)
	}
}

func (s *Suite) TestReferenceInFullResponseDisconnects(t *utesting.T) {
	t.Log(`This test answers a compact request with a reference the node cannot resolve, then
answers its full retry with the same reference. A reference in a compact 0 response is
malformed and must make the node disconnect.`)
	conn := s.dialEth76(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	f := s.fixture76(t)
	req := conn.announceAndAwaitRequest76(t, f.announcement())
	if req.Compact == 1 {
		if err := conn.serveWrappers76(req, func(common.Hash) []byte { return f.compact(t) }); err != nil {
			t.Fatal(err)
		}
		req = conn.awaitRequest76(t)
	}
	if err := conn.serveWrappers76(req, func(common.Hash) []byte { return f.compact(t) }); err != nil {
		t.Fatal(err)
	}
	if err := conn.expectDisconnect76(); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestMalformedAnnouncementDisconnects(t *utesting.T) {
	t.Log(`This test sends announcements that break EIP-8518's transport rules: more than 64
entries, and hashes out of order. Each must make the node disconnect.`)
	for _, tc := range []struct {
		name string
		anns func() []wrapperAnnouncement76
	}{
		{"too many", func() []wrapperAnnouncement76 { return sortedAnnouncements76(maxAnnounced76 + 1) }},
		{"unordered", func() []wrapperAnnouncement76 {
			anns := sortedAnnouncements76(2)
			anns[0], anns[1] = anns[1], anns[0]
			return anns
		}},
	} {
		conn := s.dialEth76(t)
		if conn == nil {
			return
		}
		if err := conn.Write(ethProto, newProofWrapperHashesMsg, tc.anns()); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		err := conn.expectDisconnect76()
		conn.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

// dialEth76 connects offering eth/76 above the versions the node may prefer instead, and
// completes the status exchange. It returns nil, logging why, if the node does not
// negotiate eth/76.
func (s *Suite) dialEth76(t *utesting.T) *Conn {
	conn, err := s.dial()
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.caps = append([]p2p.Cap{{Name: "eth", Version: eth76}}, conn.caps...)
	conn.ourHighestProtoVersion = eth76
	if err := conn.handshake(); err != nil {
		conn.Close()
		t.Fatalf("handshake failed: %v", err)
	}
	if conn.negotiatedProtoVersion != eth76 {
		conn.Close()
		t.Logf("node negotiated eth/%d rather than eth/76, skipping", conn.negotiatedProtoVersion)
		return nil
	}
	if _, err := conn.adoptStatus(); err != nil {
		conn.Close()
		t.Fatalf("status exchange failed: %v", err)
	}
	return conn
}

// fixture76 returns a wrapper fixture with its hints derived from its encoding, so that a
// test only alters what it means to.
func (s *Suite) fixture76(t *utesting.T) *wrapperFixture76 {
	f := wrapperFixtures76[0]
	if got := crypto.Keccak256Hash(f.wrapper); got != f.hash {
		t.Fatalf("fixture hashes to %v, want %v", got, f.hash)
	}
	var w struct {
		Txs   [][]byte
		Deps  [][]byte
		Proof []byte
	}
	if err := rlp.DecodeBytes(f.wrapper, &w); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	f.depsHash = crypto.Keccak256Hash(w.Deps...)
	f.txsHash = crypto.Keccak256Hash(f.txHash[:])
	f.encodingHash = crypto.Keccak256Hash(w.Txs[0])
	return &f
}

func (f *wrapperFixture76) announcement() wrapperAnnouncement76 {
	return wrapperAnnouncement76{Length: uint64(len(f.wrapper)), Hash: f.hash, DepsHash: f.depsHash, TxsHash: f.txsHash}
}

// compact returns the wrapper with its transaction replaced by [encoding-hash].
func (f *wrapperFixture76) compact(t *utesting.T) []byte {
	var w struct {
		Txs   []rlp.RawValue
		Deps  [][]byte
		Proof []byte
	}
	if err := rlp.DecodeBytes(f.wrapper, &w); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	ref, _ := rlp.EncodeToBytes([]common.Hash{f.encodingHash})
	w.Txs = []rlp.RawValue{ref}
	enc, err := rlp.EncodeToBytes(&w)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func (c *Conn) announce76(anns ...wrapperAnnouncement76) error {
	return c.Write(ethProto, newProofWrapperHashesMsg, anns)
}

func (c *Conn) announceAndAwaitRequest76(t *utesting.T, ann wrapperAnnouncement76) *getProofWrappersPacket76 {
	if err := c.announce76(ann); err != nil {
		t.Fatal(err)
	}
	return c.awaitRequest76(t)
}

// awaitRequest76 reads the node's next GetProofWrappers and checks its transport rules.
func (c *Conn) awaitRequest76(t *utesting.T) *getProofWrappersPacket76 {
	data, err := c.readEthMsg(getProofWrappersMsg, time.Now().Add(timeout))
	if err != nil {
		t.Fatalf("node did not request the announced wrapper: %v", err)
	}
	var req getProofWrappersPacket76
	if err := rlp.DecodeBytes(data, &req); err != nil {
		t.Fatalf("invalid GetProofWrappers: %v", err)
	}
	if len(req.Hashes) == 0 || len(req.Hashes) > maxRequested76 || req.Compact > 1 {
		t.Fatalf("GetProofWrappers with %d hashes and compact %d", len(req.Hashes), req.Compact)
	}
	return &req
}

// serveWrappers76 answers a GetProofWrappers request with the item serve gives each
// requested hash, in request order.
func (c *Conn) serveWrappers76(req *getProofWrappersPacket76, serve func(common.Hash) []byte) error {
	resp := &proofWrappersPacket76{RequestId: req.RequestId}
	for _, h := range req.Hashes {
		resp.Wrappers = append(resp.Wrappers, servedWrapper76{Hash: h, Wrapper: serve(h)})
	}
	return c.Write(ethProto, proofWrappersMsg, resp)
}

// checkAlive76 requests an unknown wrapper and expects the empty answer, showing that the
// connection is still open.
func (c *Conn) checkAlive76() error {
	id := randomRequestID()
	if err := c.Write(ethProto, getProofWrappersMsg, &getProofWrappersPacket76{RequestId: id, Compact: 1, Hashes: []common.Hash{randomHash()}}); err != nil {
		return err
	}
	for deadline := time.Now().Add(timeout); ; {
		data, err := c.readEthMsg(proofWrappersMsg, deadline)
		if err != nil {
			return fmt.Errorf("no ProofWrappers response: %v", err)
		}
		var resp proofWrappersPacket76
		if err := rlp.DecodeBytes(data, &resp); err != nil {
			return fmt.Errorf("invalid ProofWrappers: %v", err)
		}
		if resp.RequestId != id {
			continue
		}
		if len(resp.Wrappers) != 0 {
			return fmt.Errorf("node served %d wrappers it never announced", len(resp.Wrappers))
		}
		return nil
	}
}

// expectDisconnect76 waits for the node to close the connection.
func (c *Conn) expectDisconnect76() error {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		code, _, _, err := c.Conn.Read()
		switch {
		case err != nil:
			var netErr interface{ Timeout() bool }
			if errors.As(err, &netErr) && netErr.Timeout() {
				return errors.New("node did not disconnect")
			}
			return nil
		case code == discMsg:
			return nil
		case code == pingMsg:
			c.Write(baseProto, pongMsg, []byte{})
		}
	}
}

func sortedAnnouncements76(n int) []wrapperAnnouncement76 {
	anns := make([]wrapperAnnouncement76, n)
	for i := range anns {
		anns[i] = wrapperAnnouncement76{Length: 100, Hash: randomHash(), DepsHash: randomHash(), TxsHash: randomHash()}
	}
	slices.SortFunc(anns, func(a, b wrapperAnnouncement76) int { return bytes.Compare(a.Hash[:], b.Hash[:]) })
	return anns
}

func randomHash() (h common.Hash) {
	rand.Read(h[:])
	return h
}
