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
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e018094b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0c0a6c424ac7157ae408398df7e5f4552091a69125d5dfcb7b8c2659029395bdf8080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010c0a6c424ac7157ae408398df7e5f4552091a69125d5dfcb7b8c2659029395bdf03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0xa06e3a48cdd3d0cfa32babe50eb668aeea18fd5e882c0cc86c0ca65124128084"),
		txHash:  common.HexToHash("0x3e016fdf9e33d821259b37d81a943a289f115f24f0bc3000346afbc6747f3600"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010194b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0eedf1a9c68b3f4a8b1a1032b2b5ad5c4795c026514f8317c7a215e218dccd6cf8080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010eedf1a9c68b3f4a8b1a1032b2b5ad5c4795c026514f8317c7a215e218dccd6cf03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x44c48956e0deff2a374750eeb6897067f23e713f6781074e6848c8ce00868626"),
		txHash:  common.HexToHash("0x6b1886857fde196ef4881cf8b19165b24da669dc970b1bb126c89fa49c18cb25"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010294b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a075bf18e34f9add02a2fe5a146813eb9362372eef6200f3b1dbc3f819671cba698080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b860000000000000000000000000000000000000000000000000000000000000001075bf18e34f9add02a2fe5a146813eb9362372eef6200f3b1dbc3f819671cba6903783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0xdf89ada9e482b10dd1bafb115f45d93839c9b616f3ce505d629fee9ea2ff054b"),
		txHash:  common.HexToHash("0xb06c926407dd8460776f4b2eeee745540e40d1a8b27871f218cee9ac63c198fb"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010394b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0e8e3774d93e52335eb2f60651eff47bc3a10a45d4b230b5d10e37751fe6aa7188080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010e8e3774d93e52335eb2f60651eff47bc3a10a45d4b230b5d10e37751fe6aa71803783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x3396e1be96870b4a2b83328d9805736dde36f63484cafde9cd743fe1c468af47"),
		txHash:  common.HexToHash("0x172c66918e16b1df5253bf93af7a2583c35f328b3ac9ee931c2f7c7cab94952a"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010494b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a09206f7a6f3a7022a07f08066e1ab8145f7e55dc933d51a18c793f901a3a0b2768080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b86000000000000000000000000000000000000000000000000000000000000000109206f7a6f3a7022a07f08066e1ab8145f7e55dc933d51a18c793f901a3a0b27603783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x3992d204ad489b84b9490966b2cce5de8656a5ab6a6fb0149e26320bbfe17483"),
		txHash:  common.HexToHash("0xfa80bf8fbefd52a5e59d70090fed51c3738ff0fb116e3d1669b27d53646da354"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010594b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a043e51637a9b51e7ba9df07d8e57bfe9f44b819898f47bf37e5af72a0783e11418080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b860000000000000000000000000000000000000000000000000000000000000001043e51637a9b51e7ba9df07d8e57bfe9f44b819898f47bf37e5af72a0783e114103783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0xc18142d31ecb23a198facfb5c961242a911141694747aa85a09a4d5778a8f570"),
		txHash:  common.HexToHash("0x46ce4c471f5c4fd2271660a0e1d7363c0b35590c519e1c936e599c90198aa3e4"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010694b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a073f2a22d0902cd8d5c90937dd41c057fd1c78805aac12b0a94a405c0461a6fbb8080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b860000000000000000000000000000000000000000000000000000000000000001073f2a22d0902cd8d5c90937dd41c057fd1c78805aac12b0a94a405c0461a6fbb03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x57f4c91926b74755bb4fd8769c5dea5806523133d29576c4e618d7d962f8fe9e"),
		txHash:  common.HexToHash("0xa1d415e5c76ea306ef1b5474919d756b82f1bfd16e546aadf4cf9aa10972431d"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010794b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0e710ab856afef758692465fbf1f6619b38a98d6de0800f1defc0a6399eb6d30c8080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010e710ab856afef758692465fbf1f6619b38a98d6de0800f1defc0a6399eb6d30c03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0xaf6168171dbc3685099aa51a9251e0a7bb2e9f0cc953e1cb4f71b773a9e139f8"),
		txHash:  common.HexToHash("0xfd5a5eb2c263d8b5cfbf0bbc701c4c4b5c12986a2b3b716189f050d53b13fcf5"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010894b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a093eb76ace9641e52833ffd56f7edc8fa1ecc32967f827c9043fcae6ba73afa5c8080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b860000000000000000000000000000000000000000000000000000000000000001093eb76ace9641e52833ffd56f7edc8fa1ecc32967f827c9043fcae6ba73afa5c03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x11f0982c7f19ee0039d7f2851a44f799770d67f6a8d6f0e70bb468e0c9ab79a9"),
		txHash:  common.HexToHash("0x0bf46cd54dddf1156d453c5ab367d41f4760892f92f154f67224d180ec261692"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010994b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a09f2353bde94264dbc3d554a94cceba2d7d2b4fdce4304d3e09a1fea9fbeb15288080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b86000000000000000000000000000000000000000000000000000000000000000109f2353bde94264dbc3d554a94cceba2d7d2b4fdce4304d3e09a1fea9fbeb152803783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x76f3bece7b308af273a44ba4ec285e9acfd37fde27cef6e47b165bbf28c79c0c"),
		txHash:  common.HexToHash("0x496fbd782b41348a337714dee24e3d95745511999d3b4f82c097ba60db3ddb0d"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010a94b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0f4590461845dae2e95d134013da8d322cb2435da26e9c9fee670f9fb7fe74e498080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010f4590461845dae2e95d134013da8d322cb2435da26e9c9fee670f9fb7fe74e4903783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0xedfc1ba44b0603e5b2d8a62ef4c14b0362af447c7ba4b955416be42eaae09e67"),
		txHash:  common.HexToHash("0x74512c5043d256e669fb0dc834873087263f913a70aab18454b826a7a6bec912"),
	},
	{
		wrapper: hexutil.MustDecode("0xf90157f8edb8eb06f8e8f89e010b94b7705ae4c6f81b66cdb323c65f4e8133690fc099f875f8599400000000000000000000000000000000000081a3a003783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760a0447bc2095bfabca0f603bbd7dbc23ae43a150ff8884b02cea117b22d1c3b97968080d99400000000000000000000000000000000000081a180808080cbca010380c48203e8808080c28080c080f84480b841eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec0f862b8600000000000000000000000000000000000000000000000000000000000000010447bc2095bfabca0f603bbd7dbc23ae43a150ff8884b02cea117b22d1c3b979603783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b76083010203"),
		hash:    common.HexToHash("0x94cde322fbfc7fd2262073f131fb6c378244667e3b967fa7f5cb69b215e41cc2"),
		txHash:  common.HexToHash("0x38cde36b9b0a2830e51fc4c5e405f568e30c4b2196b2f74373e0a08f089d011b"),
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
	f := s.fixture76(t, 0)
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
	f := s.fixture76(t, 1)
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
	f := s.fixture76(t, 2)
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
	f := s.fixture76(t, 3)
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
	f := s.fixture76(t, 4)
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
	f := s.fixture76(t, 5)
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
	f := s.fixture76(t, 6)
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
//
// Each test uses its own fixture: the node remembers a wrapper it discarded or is still
// fetching, so a fixture shared across tests would not be fetched again.
func (s *Suite) fixture76(t *utesting.T, i int) *wrapperFixture76 {
	f := wrapperFixtures76[i]
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
