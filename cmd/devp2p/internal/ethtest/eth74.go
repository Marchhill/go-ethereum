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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/internal/utesting"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// eth/74 (EIP-8512) exchanges the EIP-8288 dependency proofs, which neither headers nor
// bodies carry. go-ethereum does not implement it, so its messages are defined here.

const (
	eth74 = 74

	getDependencyProofsMsg = 0x16
	dependencyProofsMsg    = 0x17

	// eth74BuiltBlocks is how many blocks the suite has the node build, so that the
	// chain it queries holds blocks the node is certain to have proofs for.
	eth74BuiltBlocks = 2
	// eth74MaxHeaders bounds how far back from the head the suite queries.
	eth74MaxHeaders = 16
)

// Positions of the block header fields the suite reads. EIP-8288 appends
// dependency_proof_hash after the Amsterdam fields.
const (
	headerNumber              = 8
	headerGasLimit            = 9
	headerTimestamp           = 11
	headerSlotNumber          = 22
	headerDependencyProofHash = 23
)

var emptyProofHash = crypto.Keccak256Hash(nil)

type getDependencyProofsPacket struct {
	RequestId uint64
	Hashes    []common.Hash
}

type dependencyProofsPacket struct {
	RequestId uint64
	Proofs    [][]byte
}

// eth74Header is the part of a block header the eth/74 tests use.
type eth74Header struct {
	hash      common.Hash
	number    uint64
	gasLimit  uint64
	time      uint64
	slot      uint64
	proofHash *common.Hash // nil before EIP-8288
	// built marks a block the suite had the node build, whose proof the node must hold.
	built bool
}

// eth74State is the chain the eth/74 tests query, set up once per suite.
type eth74State struct {
	headers []*eth74Header // ascending, ending at the head
	err     error
}

// Eth74Tests returns the eth/74 (EIP-8512) dependency proof tests. The node must run a
// chain with EIP-8288 and Amsterdam active, such as the genesis in testdata/eip8512, on
// which the suite builds blocks through the Engine API. Each test passes without checking anything if the node does not offer
// eth/74.
func (s *Suite) Eth74Tests() []utesting.Test {
	return []utesting.Test{
		{Name: "Eth74Status", Fn: s.TestEth74Status},
		{Name: "GetDependencyProofs", Fn: s.TestGetDependencyProofs},
		{Name: "GetDependencyProofsUnknown", Fn: s.TestGetDependencyProofsUnknown},
		{Name: "GetDependencyProofsRequestID", Fn: s.TestGetDependencyProofsRequestID},
	}
}

func (s *Suite) TestEth74Status(t *utesting.T) {
	t.Log(`This test offers eth/74 and checks that the node negotiates it and completes the
status exchange on it.`)
	if conn, _ := s.dialEth74(t); conn != nil {
		conn.Close()
	}
}

func (s *Suite) TestGetDependencyProofs(t *utesting.T) {
	t.Log(`This test has the node build blocks, then requests the dependency proofs of the
latest blocks of its chain. The response must echo the request id and hold one entry
per hash, each empty or hashing to its header's dependency_proof_hash, and empty for a
block before EIP-8288.`)
	conn, status := s.dialEth74(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	headers := s.eth74Chain(t, conn, status.LatestBlockHash)
	t.Logf("requesting blocks %d to %d", headers[0].number, headers[len(headers)-1].number)
	if err := conn.checkProofs(headers); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestGetDependencyProofsUnknown(t *utesting.T) {
	t.Log(`This test requests the dependency proofs of unknown block hashes around a known
one. The node must answer with an empty entry for each unknown hash, in place.`)
	conn, status := s.dialEth74(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	headers := s.eth74Chain(t, conn, status.LatestBlockHash)
	head := headers[len(headers)-1]
	if err := conn.checkProofs([]*eth74Header{nil, head, nil}); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestGetDependencyProofsRequestID(t *utesting.T) {
	t.Log(`This test sends two dependency proof requests of different lengths before reading
either response. Each response must carry the id of the request it answers.`)
	conn, status := s.dialEth74(t)
	if conn == nil {
		return
	}
	defer conn.Close()
	headers := s.eth74Chain(t, conn, status.LatestBlockHash)
	requests := map[uint64][]*eth74Header{
		randomRequestID(): {headers[len(headers)-1]},
		randomRequestID(): {headers[0], nil, headers[len(headers)-1]},
	}
	for id, req := range requests {
		if err := conn.requestProofs(id, req); err != nil {
			t.Fatal(err)
		}
	}
	for range requests {
		resp, err := conn.readProofs(time.Now().Add(timeout))
		if err != nil {
			t.Fatal(err)
		}
		req, ok := requests[resp.RequestId]
		if !ok {
			t.Fatalf("response carries request id %d, which no pending request has", resp.RequestId)
		}
		if err := checkDependencyProofs(req, resp); err != nil {
			t.Fatal(err)
		}
		delete(requests, resp.RequestId)
	}
}

// dialEth74 connects offering eth/74 next to the versions the node may prefer instead, and
// completes the status exchange. It returns nil, logging why, if the node does not
// negotiate eth/74.
func (s *Suite) dialEth74(t *utesting.T) (*Conn, *eth.StatusPacket) {
	conn, err := s.dial()
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.caps = append([]p2p.Cap{{Name: "eth", Version: eth74}}, conn.caps...)
	conn.ourHighestProtoVersion = eth74
	if err := conn.handshake(); err != nil {
		conn.Close()
		t.Fatalf("handshake failed: %v", err)
	}
	if conn.negotiatedProtoVersion != eth74 {
		conn.Close()
		t.Logf("node negotiated eth/%d rather than eth/74, skipping", conn.negotiatedProtoVersion)
		return nil, nil
	}
	status, err := conn.adoptStatus()
	if err != nil {
		conn.Close()
		t.Fatalf("status exchange failed: %v", err)
	}
	return conn, status
}

// eth74Chain returns the latest headers of the node's chain, ascending. The first call has
// the node build eth74BuiltBlocks blocks on its head.
func (s *Suite) eth74Chain(t *utesting.T, conn *Conn, head common.Hash) []*eth74Header {
	s.eth74Once.Do(func() { s.eth74.headers, s.eth74.err = s.buildEth74Chain(conn, head) })
	if s.eth74.err != nil {
		t.Fatal(s.eth74.err)
	}
	return s.eth74.headers
}

func (s *Suite) buildEth74Chain(conn *Conn, headHash common.Hash) ([]*eth74Header, error) {
	head, err := conn.header(headHash)
	if err != nil {
		return nil, err
	}
	built := make(map[common.Hash]bool, eth74BuiltBlocks)
	for range eth74BuiltBlocks {
		hash, err := s.engine.buildBlock(head)
		if err != nil {
			return nil, fmt.Errorf("node did not build a block on %d: %v", head.number, err)
		}
		built[hash] = true
		if head, err = conn.header(hash); err != nil {
			return nil, err
		}
	}
	headers, err := conn.headers(head.hash, min(head.number+1, eth74MaxHeaders))
	if err != nil {
		return nil, err
	}
	for _, h := range headers {
		h.built = built[h.hash]
	}
	return headers, nil
}

// checkProofs requests the proofs of the given blocks, nil standing for an unknown hash,
// and checks the response.
func (c *Conn) checkProofs(headers []*eth74Header) error {
	id := randomRequestID()
	if err := c.requestProofs(id, headers); err != nil {
		return err
	}
	resp, err := c.readProofs(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	if resp.RequestId != id {
		return fmt.Errorf("response carries request id %d, want %d", resp.RequestId, id)
	}
	return checkDependencyProofs(headers, resp)
}

func (c *Conn) requestProofs(id uint64, headers []*eth74Header) error {
	hashes := make([]common.Hash, len(headers))
	for i, h := range headers {
		if h == nil {
			rand.Read(hashes[i][:])
		} else {
			hashes[i] = h.hash
		}
	}
	return c.Write(ethProto, getDependencyProofsMsg, &getDependencyProofsPacket{RequestId: id, Hashes: hashes})
}

func (c *Conn) readProofs(deadline time.Time) (*dependencyProofsPacket, error) {
	data, err := c.readEthMsg(dependencyProofsMsg, deadline)
	if err != nil {
		return nil, fmt.Errorf("no DependencyProofs response: %v", err)
	}
	var resp dependencyProofsPacket
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		return nil, fmt.Errorf("invalid DependencyProofs: %v", err)
	}
	return &resp, nil
}

// checkDependencyProofs checks a response to a request for the given blocks, nil standing
// for an unknown hash. The requests of these tests are far below the 2 MiB soft limit, so
// the response must cover all of them.
func checkDependencyProofs(headers []*eth74Header, resp *dependencyProofsPacket) error {
	if len(resp.Proofs) != len(headers) {
		return fmt.Errorf("response has %d entries for %d hashes", len(resp.Proofs), len(headers))
	}
	for i, h := range headers {
		proof := resp.Proofs[i]
		switch {
		case h == nil:
			if len(proof) != 0 {
				return fmt.Errorf("entry %d: %d-byte proof for an unknown block", i, len(proof))
			}
		case h.proofHash == nil:
			if len(proof) != 0 {
				return fmt.Errorf("entry %d: %d-byte proof for block %d, which predates EIP-8288", i, len(proof), h.number)
			}
		case len(proof) != 0:
			if got := crypto.Keccak256Hash(proof); got != *h.proofHash {
				return fmt.Errorf("entry %d: proof of block %d hashes to %v, header commits to %v", i, h.number, got, *h.proofHash)
			}
		case h.built && *h.proofHash != emptyProofHash:
			return fmt.Errorf("entry %d: no proof for block %d, which the node built", i, h.number)
		}
	}
	return nil
}

// readEthMsg returns the payload of the next eth message with the given code, answering
// pings and skipping other messages.
func (c *Conn) readEthMsg(code uint64, deadline time.Time) ([]byte, error) {
	c.SetReadDeadline(deadline)
	for {
		got, data, _, err := c.Conn.Read()
		if err != nil {
			return nil, err
		}
		switch got {
		case discMsg:
			return nil, errDisc
		case pingMsg:
			c.Write(baseProto, pongMsg, []byte{})
		case protoOffset(ethProto) + code:
			return data, nil
		}
	}
}

// header fetches the header of the given block.
func (c *Conn) header(hash common.Hash) (*eth74Header, error) {
	headers, err := c.headers(hash, 1)
	if err != nil {
		return nil, err
	}
	return headers[0], nil
}

// headers fetches count headers ending at the given block, ascending.
func (c *Conn) headers(last common.Hash, count uint64) ([]*eth74Header, error) {
	headers, err := c.requestHeaders(&eth.GetBlockHeadersRequest{Origin: eth.HashOrNumber{Hash: last}, Amount: count, Reverse: true})
	if err != nil {
		return nil, err
	}
	if uint64(len(headers)) != count || headers[0].hash != last {
		return nil, fmt.Errorf("node returned %d headers ending at %v, want %d ending at %v", len(headers), headers[0].hash, count, last)
	}
	for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
		headers[i], headers[j] = headers[j], headers[i]
	}
	return headers, nil
}

func (c *Conn) requestHeaders(req *eth.GetBlockHeadersRequest) ([]*eth74Header, error) {
	id := randomRequestID()
	if err := c.Write(ethProto, eth.GetBlockHeadersMsg, &eth.GetBlockHeadersPacket{RequestId: id, GetBlockHeadersRequest: req}); err != nil {
		return nil, err
	}
	data, err := c.readEthMsg(eth.BlockHeadersMsg, time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("no BlockHeaders response: %v", err)
	}
	var resp struct {
		RequestId uint64
		Headers   []rlp.RawValue
	}
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		return nil, fmt.Errorf("invalid BlockHeaders: %v", err)
	}
	if resp.RequestId != id {
		return nil, fmt.Errorf("BlockHeaders for request %d, want %d", resp.RequestId, id)
	}
	if len(resp.Headers) == 0 {
		return nil, errors.New("node returned no headers")
	}
	headers := make([]*eth74Header, len(resp.Headers))
	for i, raw := range resp.Headers {
		if headers[i], err = decodeEth74Header(raw); err != nil {
			return nil, err
		}
	}
	return headers, nil
}

// decodeEth74Header reads the fields the tests use from an encoded header. go-ethereum's
// header type has no EIP-8288 fields and rejects headers that carry them.
func decodeEth74Header(raw rlp.RawValue) (*eth74Header, error) {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid header: %v", err)
	}
	var fields [][]byte
	for len(content) > 0 {
		var field []byte
		if _, field, content, err = rlp.Split(content); err != nil {
			return nil, fmt.Errorf("invalid header: %v", err)
		}
		fields = append(fields, field)
	}
	if len(fields) <= headerTimestamp {
		return nil, fmt.Errorf("header has %d fields", len(fields))
	}
	h := &eth74Header{
		hash:     crypto.Keccak256Hash(raw),
		number:   uint64Field(fields[headerNumber]),
		gasLimit: uint64Field(fields[headerGasLimit]),
		time:     uint64Field(fields[headerTimestamp]),
	}
	if len(fields) > headerSlotNumber {
		h.slot = uint64Field(fields[headerSlotNumber])
	}
	if len(fields) > headerDependencyProofHash {
		if len(fields[headerDependencyProofHash]) != common.HashLength {
			return nil, fmt.Errorf("header %d has a %d-byte dependency_proof_hash", h.number, len(fields[headerDependencyProofHash]))
		}
		proofHash := common.BytesToHash(fields[headerDependencyProofHash])
		h.proofHash = &proofHash
	}
	return h, nil
}

func uint64Field(b []byte) uint64 {
	var buf [8]byte
	copy(buf[8-min(len(b), 8):], b)
	return binary.BigEndian.Uint64(buf[:])
}

func randomRequestID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// buildBlock has the node build an empty Amsterdam block on parent, import it and make it
// the head, and returns its hash.
func (ec *EngineClient) buildBlock(parent *eth74Header) (common.Hash, error) {
	state := map[string]common.Hash{
		"headBlockHash":      parent.hash,
		"safeBlockHash":      parent.hash,
		"finalizedBlockHash": parent.hash,
	}
	attrs := map[string]any{
		"timestamp":             hexutil.Uint64(parent.time + 12),
		"prevRandao":            common.Hash{},
		"suggestedFeeRecipient": common.Address{},
		"withdrawals":           []any{},
		"parentBeaconBlockRoot": common.Hash{},
		"targetGasLimit":        hexutil.Uint64(parent.gasLimit),
		"slotNumber":            hexutil.Uint64(parent.slot + 1),
	}
	var fcu struct {
		PayloadStatus engineStatus   `json:"payloadStatus"`
		PayloadID     *hexutil.Bytes `json:"payloadId"`
	}
	if err := ec.rpc("engine_forkchoiceUpdatedV4", &fcu, state, attrs); err != nil {
		return common.Hash{}, err
	}
	if fcu.PayloadID == nil {
		return common.Hash{}, fmt.Errorf("forkchoice update started no payload: %v", fcu.PayloadStatus)
	}
	time.Sleep(time.Second)
	var built struct {
		ExecutionPayload  json.RawMessage `json:"executionPayload"`
		ExecutionRequests []hexutil.Bytes `json:"executionRequests"`
	}
	if err := ec.rpc("engine_getPayloadV7", &built, fcu.PayloadID); err != nil {
		return common.Hash{}, err
	}
	var payload struct {
		BlockHash common.Hash `json:"blockHash"`
	}
	if err := json.Unmarshal(built.ExecutionPayload, &payload); err != nil {
		return common.Hash{}, err
	}
	if built.ExecutionRequests == nil {
		built.ExecutionRequests = []hexutil.Bytes{}
	}
	var status engineStatus
	if err := ec.rpc("engine_newPayloadV7", &status, built.ExecutionPayload, []common.Hash{}, common.Hash{}, built.ExecutionRequests, []hexutil.Bytes{}); err != nil {
		return common.Hash{}, err
	}
	if status.Status != "VALID" {
		return common.Hash{}, fmt.Errorf("node rejected its own payload: %v", status)
	}
	state = map[string]common.Hash{
		"headBlockHash":      payload.BlockHash,
		"safeBlockHash":      payload.BlockHash,
		"finalizedBlockHash": payload.BlockHash,
	}
	if err := ec.rpc("engine_forkchoiceUpdatedV4", &fcu, state, nil); err != nil {
		return common.Hash{}, err
	}
	if fcu.PayloadStatus.Status != "VALID" {
		return common.Hash{}, fmt.Errorf("forkchoice update to the built block: %v", fcu.PayloadStatus)
	}
	return payload.BlockHash, nil
}

type engineStatus struct {
	Status          string  `json:"status"`
	ValidationError *string `json:"validationError"`
}

func (s engineStatus) String() string {
	if s.ValidationError != nil {
		return s.Status + ": " + *s.ValidationError
	}
	return s.Status
}

// rpc sends an Engine API request and decodes its result.
func (ec *EngineClient) rpc(method string, result any, params ...any) error {
	body, err := rpcRequest(method, params...)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, ec.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ec.token())
	res, err := ec.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&reply); err != nil {
		return fmt.Errorf("%s: %v", method, err)
	}
	if reply.Error != nil {
		return fmt.Errorf("%s: %d %s", method, reply.Error.Code, reply.Error.Message)
	}
	return json.Unmarshal(reply.Result, result)
}
