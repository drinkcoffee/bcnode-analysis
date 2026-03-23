// Package eth implements the Ethereum ETH wire sub-protocol (eth/67, eth/68)
// on top of a DevP2P connection. It handles the Status handshake and
// block header retrieval.
package eth

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/peterrobinson/bcnode-analysis/internal/devp2p"
)

// ETH protocol message codes (before adding the offset from base protocol length).
const (
	StatusMsg          uint64 = 0x00
	GetBlockHeadersMsg uint64 = 0x03
	BlockHeadersMsg    uint64 = 0x04
)

// StatusPacket is the ETH wire protocol Status message.
// Both sides send this after the DevP2P Hello exchange.
type StatusPacket struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	Head            common.Hash
	Genesis         common.Hash
	ForkID          forkid.ID
}

// getBlockHeadersRequest is the inner request struct for GetBlockHeaders.
// Origin is encoded as uint64 (block number), which RLP encodes as <= 8 bytes,
// matching go-ethereum's HashOrNumber decoder for the "number" case.
type getBlockHeadersRequest struct {
	Origin  uint64
	Amount  uint64
	Skip    uint64
	Reverse bool
}

// getBlockHeadersPacket is the full request packet with request ID.
// The embedded pointer encodes as a nested RLP list, matching the eth/66+ wire format:
// [request_id, [origin, amount, skip, reverse]]
type getBlockHeadersPacket struct {
	RequestId uint64
	*getBlockHeadersRequest
}

// getBlockHeadersByHashRequest uses a hash for origin instead of number.
type getBlockHeadersByHashRequest struct {
	Origin  common.Hash
	Amount  uint64
	Skip    uint64
	Reverse bool
}

// hashOrNumberEncoder handles the custom encoding where either a hash (32 bytes)
// or a number (compact integer) is used.
type hashOrNumberEncoder struct {
	isHash bool
	hash   common.Hash
	number uint64
}

func (h hashOrNumberEncoder) EncodeRLP(w io.Writer) error {
	if h.isHash {
		return rlp.Encode(w, h.hash)
	}
	return rlp.Encode(w, h.number)
}

// getBlockHeadersByHashPacket is the full request packet when using a hash origin.
type getBlockHeadersByHashPacket struct {
	RequestId uint64
	Inner     struct {
		Origin  hashOrNumberEncoder
		Amount  uint64
		Skip    uint64
		Reverse bool
	}
}

// blockHeadersPacket is the response to GetBlockHeaders.
// Wire format: [request_id, [header1, header2, ...]]
type blockHeadersPacket struct {
	RequestId uint64
	Headers   []*types.Header
}

// BlockHeader is a simplified block header for display.
type BlockHeader struct {
	Number     uint64
	Hash       string
	ParentHash string
	Time       uint64
	TxCount    int
	GasUsed    uint64
	GasLimit   uint64
	Coinbase   string
	Difficulty *big.Int
	ExtraData  []byte
}

// chainConfigs maps chain name to chain config and genesis hash.
var chainConfigs = map[string]struct {
	config  *params.ChainConfig
	genesis common.Hash
}{
	"mainnet": {
		config:  params.MainnetChainConfig,
		genesis: common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
	},
	"goerli": {
		config:  params.GoerliChainConfig,
		genesis: common.HexToHash("0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a"),
	},
	"sepolia": {
		config:  params.SepoliaChainConfig,
		genesis: common.HexToHash("0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"),
	},
	"holesky": {
		config:  params.HoleskyChainConfig,
		genesis: common.HexToHash("0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4"),
	},
}

// Peer wraps a DevP2P connection and speaks the ETH sub-protocol.
type Peer struct {
	conn   *devp2p.Conn
	offset uint64 // eth message code offset in the wire (BaseProtocolLength = 16)
	chain  string // chain name for fork ID computation
	reqID  uint64 // monotonically increasing request ID
}

// NewPeer creates a new ETH protocol peer from an established DevP2P connection.
func NewPeer(conn *devp2p.Conn, chain string) *Peer {
	return &Peer{
		conn:   conn,
		offset: devp2p.BaseProtocolLength,
		chain:  chain,
		reqID:  1,
	}
}

// Status exchanges ETH Status messages and returns the peer's status.
// We send a status with our best guess at the fork ID. The peer will send
// their status back before validating ours, so we always learn their state.
func (p *Peer) Status() (*StatusPacket, error) {
	ourStatus := p.buildOurStatus()

	if err := p.conn.Write(p.offset+StatusMsg, ourStatus); err != nil {
		return nil, fmt.Errorf("send status: %w", err)
	}

	return p.readStatus()
}

// readStatus reads messages until it receives the peer's Status.
func (p *Peer) readStatus() (*StatusPacket, error) {
	for {
		code, data, err := p.conn.Read()
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}

		// Handle base protocol messages (below the eth offset)
		if code < p.offset {
			switch code {
			case devp2p.DisconnectMsg:
				return nil, fmt.Errorf("peer disconnected before sending status")
			case devp2p.PingMsg:
				// Must respond to pings or the peer will time us out
				p.conn.Write(devp2p.PongMsg, struct{}{})
			}
			continue
		}

		switch code - p.offset {
		case StatusMsg:
			var status StatusPacket
			if err := rlp.DecodeBytes(data, &status); err != nil {
				return nil, fmt.Errorf("decode status: %w", err)
			}
			return &status, nil
		}
		// Ignore other eth messages (NewBlockHashes, Transactions, etc.)
	}
}

// GetHeadersByNumber fetches block headers starting at a given block number.
// Requires a prior Status exchange to have succeeded.
func (p *Peer) GetHeadersByNumber(start, count, skip uint64, reverse bool) ([]*BlockHeader, error) {
	p.reqID++
	req := &getBlockHeadersPacket{
		RequestId: p.reqID,
		getBlockHeadersRequest: &getBlockHeadersRequest{
			Origin:  start,
			Amount:  count,
			Skip:    skip,
			Reverse: reverse,
		},
	}
	if err := p.conn.Write(p.offset+GetBlockHeadersMsg, req); err != nil {
		return nil, fmt.Errorf("send GetBlockHeaders: %w", err)
	}
	return p.readHeaders(p.reqID)
}

// GetHeadersByHash fetches block headers starting at a given block hash.
func (p *Peer) GetHeadersByHash(hash common.Hash, count, skip uint64, reverse bool) ([]*BlockHeader, error) {
	p.reqID++
	pkt := getBlockHeadersByHashPacket{RequestId: p.reqID}
	pkt.Inner.Origin = hashOrNumberEncoder{isHash: true, hash: hash}
	pkt.Inner.Amount = count
	pkt.Inner.Skip = skip
	pkt.Inner.Reverse = reverse

	if err := p.conn.Write(p.offset+GetBlockHeadersMsg, pkt); err != nil {
		return nil, fmt.Errorf("send GetBlockHeaders: %w", err)
	}
	return p.readHeaders(p.reqID)
}

// readHeaders reads messages until BlockHeaders arrives for the given requestId.
func (p *Peer) readHeaders(reqID uint64) ([]*BlockHeader, error) {
	deadline := time.Now().Add(30 * time.Second)
	p.conn.SetDeadline(deadline)

	for {
		code, data, err := p.conn.Read()
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}

		if code < p.offset {
			switch code {
			case devp2p.DisconnectMsg:
				return nil, fmt.Errorf("peer disconnected")
			case devp2p.PingMsg:
				p.conn.Write(devp2p.PongMsg, struct{}{})
			}
			continue
		}

		if code-p.offset == BlockHeadersMsg {
			var pkt blockHeadersPacket
			if err := rlp.DecodeBytes(data, &pkt); err != nil {
				return nil, fmt.Errorf("decode BlockHeaders: %w", err)
			}
			if pkt.RequestId != reqID {
				continue // different request, skip
			}
			return convertHeaders(pkt.Headers), nil
		}
	}
}

// buildOurStatus constructs a StatusPacket to send to the peer.
// Uses the chain config to compute the correct fork ID.
func (p *Peer) buildOurStatus() StatusPacket {
	genesisHash := common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	config := params.MainnetChainConfig

	if cc, ok := chainConfigs[p.chain]; ok {
		genesisHash = cc.genesis
		config = cc.config
	}

	// Compute fork ID manually: crc32 over the genesis hash bytes, then accumulate
	// all fork block/time numbers that are <= our claimed head/time.
	// This mirrors forkid.NewID but without needing a *types.Block.
	forkID := computeForkID(config, genesisHash)

	return StatusPacket{
		ProtocolVersion: uint32(p.conn.EthVersion),
		NetworkID:       chainNetworkID(p.chain),
		TD:              new(big.Int),
		Head:            genesisHash, // pretend we only have genesis
		Genesis:         genesisHash,
		ForkID:          forkID,
	}
}

// computeForkID computes a forkid.ID from a chain config and known genesis hash,
// without requiring a *types.Block. We claim to be at a very high head block and
// current time so that all known forks are accumulated into the checksum.
func computeForkID(config *params.ChainConfig, genesisHash common.Hash) forkid.ID {
	// Start from the genesis hash checksum (same as forkid.NewID)
	h := crc32.ChecksumIEEE(genesisHash.Bytes())

	headBlock := uint64(21_000_000)
	headTime := uint64(time.Now().Unix())

	// Gather all block-based forks from the chain config, sorted ascending.
	// We replicate the logic from gatherForks in core/forkid.
	blockForks := gatherBlockForks(config)
	timeForks := gatherTimeForks(config)

	var nextFork uint64
	for _, fork := range blockForks {
		if fork <= headBlock {
			h = crc32UpdateUint64(h, fork)
		} else {
			nextFork = fork
			break
		}
	}
	if nextFork == 0 {
		for _, fork := range timeForks {
			if fork <= headTime {
				h = crc32UpdateUint64(h, fork)
			} else {
				nextFork = fork
				break
			}
		}
	}

	var hashBytes [4]byte
	binary.BigEndian.PutUint32(hashBytes[:], h)
	return forkid.ID{Hash: hashBytes, Next: nextFork}
}

func crc32UpdateUint64(h uint32, v uint64) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return crc32.Update(h, crc32.IEEETable, buf[:])
}

// gatherBlockForks returns all unique non-zero block-number fork points, sorted ascending.
func gatherBlockForks(config *params.ChainConfig) []uint64 {
	var forks []uint64
	seen := make(map[uint64]bool)
	add := func(b *big.Int) {
		if b == nil || b.Sign() == 0 {
			return
		}
		v := b.Uint64()
		if !seen[v] {
			seen[v] = true
			forks = append(forks, v)
		}
	}
	add(config.HomesteadBlock)
	add(config.DAOForkBlock)
	add(config.EIP150Block)
	add(config.EIP155Block)
	add(config.EIP158Block)
	add(config.ByzantiumBlock)
	add(config.ConstantinopleBlock)
	add(config.PetersburgBlock)
	add(config.IstanbulBlock)
	add(config.MuirGlacierBlock)
	add(config.BerlinBlock)
	add(config.LondonBlock)
	add(config.ArrowGlacierBlock)
	add(config.GrayGlacierBlock)
	add(config.MergeNetsplitBlock)
	// Sort
	for i := 1; i < len(forks); i++ {
		for j := i; j > 0 && forks[j] < forks[j-1]; j-- {
			forks[j], forks[j-1] = forks[j-1], forks[j]
		}
	}
	return forks
}

// gatherTimeForks returns all unique non-zero timestamp-based fork points, sorted ascending.
func gatherTimeForks(config *params.ChainConfig) []uint64 {
	var forks []uint64
	seen := make(map[uint64]bool)
	add := func(t *uint64) {
		if t == nil || *t == 0 {
			return
		}
		if !seen[*t] {
			seen[*t] = true
			forks = append(forks, *t)
		}
	}
	add(config.ShanghaiTime)
	add(config.CancunTime)
	add(config.PragueTime)
	// Sort
	for i := 1; i < len(forks); i++ {
		for j := i; j > 0 && forks[j] < forks[j-1]; j-- {
			forks[j], forks[j-1] = forks[j-1], forks[j]
		}
	}
	return forks
}

func chainNetworkID(chain string) uint64 {
	switch chain {
	case "sepolia":
		return 11155111
	case "holesky":
		return 17000
	case "goerli":
		return 5
	default:
		return 1 // mainnet
	}
}

// convertHeaders converts go-ethereum types.Header to our simplified BlockHeader.
func convertHeaders(headers []*types.Header) []*BlockHeader {
	result := make([]*BlockHeader, len(headers))
	for i, h := range headers {
		txCount := 0
		if h.TxHash != types.EmptyTxsHash {
			txCount = -1 // headers don't carry the actual tx count; -1 means "has transactions"
		}
		result[i] = &BlockHeader{
			Number:     h.Number.Uint64(),
			Hash:       h.Hash().Hex(),
			ParentHash: h.ParentHash.Hex(),
			Time:       h.Time,
			TxCount:    txCount,
			GasUsed:    h.GasUsed,
			GasLimit:   h.GasLimit,
			Coinbase:   h.Coinbase.Hex(),
			Difficulty: h.Difficulty,
			ExtraData:  h.Extra,
		}
	}
	return result
}
