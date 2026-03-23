// Package devp2p implements the Ethereum DevP2P wire protocol over RLPx.
// It handles the RLPx encrypted transport handshake and the DevP2P Hello
// message exchange to establish a connection to an Ethereum node.
package devp2p

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

// Base protocol message codes (DevP2P spec)
const (
	HelloMsg      uint64 = 0x00
	DisconnectMsg uint64 = 0x01
	PingMsg       uint64 = 0x02
	PongMsg       uint64 = 0x03

	// BaseProtocolLength is the number of message code slots reserved for the
	// base DevP2P protocol. Sub-protocols (e.g. eth) are offset by this amount.
	BaseProtocolLength uint64 = 16
)

// disconnectReasons maps disconnect reason codes to human-readable descriptions.
var disconnectReasons = map[uint64]string{
	0:  "disconnect requested",
	1:  "network error",
	2:  "breach of protocol",
	3:  "useless peer",
	4:  "too many peers",
	5:  "already connected",
	6:  "incompatible p2p protocol version",
	7:  "null node identity",
	8:  "client quitting",
	9:  "unexpected identity",
	10: "connected to self",
	11: "ping timeout",
	16: "subprotocol error",
}

// Capability represents a DevP2P sub-protocol capability (e.g. {eth, 68}).
type Capability struct {
	Name    string
	Version uint
}

func (c Capability) String() string {
	return fmt.Sprintf("%s/%d", c.Name, c.Version)
}

// HelloPacket is the DevP2P p2p/hello message (code 0x00).
// Both sides send this immediately after the RLPx handshake.
type HelloPacket struct {
	Version    uint64
	Name       string       // client identifier string
	Caps       []Capability // supported sub-protocols
	ListenPort uint64       // listening TCP port (0 = not listening)
	ID         []byte       // 64-byte uncompressed secp256k1 public key (no 0x04 prefix)
	Rest       []rlp.RawValue `rlp:"tail"`
}

// Conn wraps an RLPx connection with DevP2P protocol support.
type Conn struct {
	rw         *rlpx.Conn
	privKey    *ecdsa.PrivateKey
	OurHello   HelloPacket
	TheirHello HelloPacket
	EthVersion uint // highest mutually supported eth protocol version (0 if none)
}

// Dial connects to an Ethereum node by its enode URL, performs the RLPx
// encrypted handshake, and exchanges DevP2P Hello messages.
func Dial(rawEnode string, timeout time.Duration) (*Conn, error) {
	node, err := enode.ParseV4(rawEnode)
	if err != nil {
		return nil, fmt.Errorf("invalid enode URL: %w", err)
	}

	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", node.IP().String(), node.TCP())
	tcpConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	tcpConn.SetDeadline(time.Now().Add(timeout))

	rlpxConn := rlpx.NewConn(tcpConn, node.Pubkey())
	if _, err := rlpxConn.Handshake(privKey); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("RLPx handshake: %w", err)
	}

	// Strip the 0x04 uncompressed prefix byte from our public key
	pubBytes := crypto.FromECDSAPub(&privKey.PublicKey)

	c := &Conn{
		rw:      rlpxConn,
		privKey: privKey,
		OurHello: HelloPacket{
			Version: 5,
			Name:    "gnode/v0.1.0/go",
			Caps: []Capability{
				{Name: "eth", Version: 68},
				{Name: "eth", Version: 67},
			},
			ListenPort: 0,
			ID:         pubBytes[1:],
		},
	}

	if err := c.doHello(); err != nil {
		rlpxConn.Close()
		return nil, err
	}

	return c, nil
}

// doHello sends our Hello and reads the peer's Hello, performing capability negotiation.
func (c *Conn) doHello() error {
	helloData, err := rlp.EncodeToBytes(c.OurHello)
	if err != nil {
		return fmt.Errorf("encode hello: %w", err)
	}
	if _, err := c.rw.Write(HelloMsg, helloData); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	code, data, _, err := c.rw.Read()
	if err != nil {
		return fmt.Errorf("read hello response: %w", err)
	}

	switch code {
	case HelloMsg:
		if err := rlp.DecodeBytes(data, &c.TheirHello); err != nil {
			return fmt.Errorf("decode peer hello: %w", err)
		}
	case DisconnectMsg:
		var disc struct {
			Reason uint64
			Rest   []rlp.RawValue `rlp:"tail"`
		}
		rlp.DecodeBytes(data, &disc)
		reason := disconnectReasons[disc.Reason]
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("peer disconnected before hello: %s (code %d)", reason, disc.Reason)
	default:
		return fmt.Errorf("expected hello (0x00), got message code 0x%02x", code)
	}

	c.EthVersion = c.negotiateEthVersion()
	return nil
}

// negotiateEthVersion returns the highest eth protocol version both sides support.
func (c *Conn) negotiateEthVersion() uint {
	ours := make(map[uint]bool)
	for _, cap := range c.OurHello.Caps {
		if cap.Name == "eth" {
			ours[cap.Version] = true
		}
	}
	var best uint
	for _, cap := range c.TheirHello.Caps {
		if cap.Name == "eth" && ours[cap.Version] {
			if cap.Version > best {
				best = cap.Version
			}
		}
	}
	return best
}

// Write sends a DevP2P message. The payload is RLP-encoded automatically.
func (c *Conn) Write(code uint64, payload interface{}) error {
	data, err := rlp.EncodeToBytes(payload)
	if err != nil {
		return fmt.Errorf("encode message 0x%02x: %w", code, err)
	}
	_, err = c.rw.Write(code, data)
	return err
}

// Read reads the next DevP2P message, returning the code and raw RLP payload.
func (c *Conn) Read() (uint64, []byte, error) {
	code, data, _, err := c.rw.Read()
	return code, data, err
}

// Ping sends a ping message and waits for a pong, measuring latency.
func (c *Conn) Ping() error {
	if _, err := c.rw.Write(PingMsg, []byte{0xC0}); err != nil {
		return err
	}
	for {
		code, _, _, err := c.rw.Read()
		if err != nil {
			return err
		}
		if code == PongMsg {
			return nil
		}
		if code == DisconnectMsg {
			return fmt.Errorf("peer disconnected during ping")
		}
		// Ignore other messages (e.g. sub-protocol traffic)
	}
}

// SetDeadline sets the connection deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.rw.SetDeadline(t)
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.rw.Close()
}
