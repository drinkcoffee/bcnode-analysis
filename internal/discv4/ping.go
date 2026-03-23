// Package discv4 implements just enough of the Ethereum Node Discovery v4
// protocol (EIP-778 / discv4) to recover a node's public key from its
// UDP address. It sends a signed Ping and extracts the sender's secp256k1
// public key from the cryptographic signature on the response.
package discv4

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Wire format sizes (bytes)
const (
	macSize  = 32 // keccak256 hash of everything after it
	sigSize  = 65 // recoverable secp256k1 signature
	headSize = macSize + sigSize
)

// discv4 packet type bytes
const (
	pingPacket = 1
	pongPacket = 2
)

// endpoint is the IP/UDP/TCP address tuple used in discv4 packets.
// The IP must be exactly 4 bytes (IPv4) or 16 bytes (IPv6) for correct
// RLP encoding on the wire.
type endpoint struct {
	IP  net.IP
	UDP uint16
	TCP uint16
}

// ping is the discv4 Ping packet (packet type 1).
type ping struct {
	Version    uint
	From, To   endpoint
	Expiration uint64
	// ENRSeq and tail fields omitted — we only need the base fields
}

// pong is the discv4 Pong packet (packet type 2).
type pong struct {
	To         endpoint
	ReplyTok   []byte // hash of the Ping we're replying to
	Expiration uint64
}

// encodePacket signs and encodes a discv4 packet.
//
// Wire layout:
//
//	[0:32]  = keccak256( packet[32:] )           — integrity hash (MAC)
//	[32:97] = secp256k1_sign( keccak256( packet[97:] ) )  — signature
//	[97]    = packet type byte
//	[98:]   = RLP-encoded packet payload
func encodePacket(priv *ecdsa.PrivateKey, ptype byte, data interface{}) (packet []byte, hash []byte, err error) {
	body, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, nil, fmt.Errorf("rlp encode: %w", err)
	}

	// sigdata = type || RLP(payload) — what gets signed
	sigdata := make([]byte, 1+len(body))
	sigdata[0] = ptype
	copy(sigdata[1:], body)

	sig, err := crypto.Sign(crypto.Keccak256(sigdata), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}

	// Assemble full packet: [zeros(32)][sig(65)][sigdata]
	packet = make([]byte, headSize+len(sigdata))
	copy(packet[macSize:headSize], sig)
	copy(packet[headSize:], sigdata)

	// Fill in the MAC: keccak256(packet[32:])
	hash = crypto.Keccak256(packet[macSize:])
	copy(packet[:macSize], hash)

	return packet, hash, nil
}

// decodePacket verifies the MAC, recovers the sender's public key from the
// signature, and decodes the packet type and RLP payload.
// Returns: packet-type, RLP payload bytes, sender pubkey, error.
func decodePacket(data []byte) (ptype byte, body []byte, pubKey *ecdsa.PublicKey, err error) {
	if len(data) < headSize+1 {
		return 0, nil, nil, errors.New("packet too short")
	}

	mac := data[:macSize]
	sig := data[macSize:headSize]
	sigdata := data[headSize:] // type || RLP(payload)

	// Verify integrity hash
	expectedMAC := crypto.Keccak256(data[macSize:])
	for i := range mac {
		if mac[i] != expectedMAC[i] {
			return 0, nil, nil, errors.New("bad packet hash")
		}
	}

	// Recover sender's public key from signature over keccak256(sigdata)
	pubBytes, err := crypto.Ecrecover(crypto.Keccak256(sigdata), sig)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("recover pubkey: %w", err)
	}
	pubKey, err = crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("unmarshal pubkey: %w", err)
	}

	return sigdata[0], sigdata[1:], pubKey, nil
}

// canonicalIP returns the most compact representation of an IP:
// 4 bytes for IPv4, 16 bytes for IPv6.
func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// PingResult holds the information recovered from a discv4 handshake.
type PingResult struct {
	PubKey  *ecdsa.PublicKey
	TCPPort int // P2P TCP port reported by the node (0 = unknown, use UDP port)
}

// Ping sends a discv4 Ping to targetAddr and returns the node's public key.
//
// The discv4 handshake works as follows:
//  1. We send a signed Ping to the target.
//  2. If the target doesn't know us it sends us a Ping first (to verify we
//     are reachable). We reply with a Pong and extract the key from the Ping.
//  3. If the target knows us it replies directly with a Pong.
//
// In both cases the sender's public key is embedded in the packet signature.
func Ping(targetAddr *net.UDPAddr, timeout time.Duration) (*PingResult, error) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("bind UDP socket: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	targetIP := canonicalIP(targetAddr.IP)

	// Build and send a Ping
	outPing := ping{
		Version:    4,
		From:       endpoint{IP: net.IP{0, 0, 0, 0}, UDP: uint16(localAddr.Port), TCP: 0},
		To:         endpoint{IP: targetIP, UDP: uint16(targetAddr.Port), TCP: uint16(targetAddr.Port)},
		Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
	}
	outData, _, err := encodePacket(priv, pingPacket, outPing)
	if err != nil {
		return nil, fmt.Errorf("encode ping: %w", err)
	}
	if _, err := conn.WriteTo(outData, targetAddr); err != nil {
		return nil, fmt.Errorf("send ping to %s: %w", targetAddr, err)
	}

	// Read responses, accepting only packets from the target
	buf := make([]byte, 1280) // max discv4 packet size
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, fmt.Errorf("no response from %s within %s (node may be offline or UDP is firewalled)", targetAddr, timeout)
			}
			return nil, fmt.Errorf("read UDP: %w", err)
		}

		fromUDP, ok := from.(*net.UDPAddr)
		if !ok || !canonicalIP(fromUDP.IP).Equal(targetIP) {
			continue // ignore packets not from our target
		}

		ptype, body, pubKey, err := decodePacket(buf[:n])
		if err != nil {
			continue // ignore malformed packets
		}

		result := &PingResult{PubKey: pubKey}

		switch ptype {
		case pingPacket:
			// Target is verifying us — decode to learn their TCP port
			var theirPing ping
			if err := rlp.DecodeBytes(body, &theirPing); err == nil && theirPing.From.TCP != 0 {
				result.TCPPort = int(theirPing.From.TCP)
			}
			// Reply with Pong (polite and needed for the handshake to complete)
			replyPong := pong{
				To:         endpoint{IP: fromUDP.IP, UDP: uint16(fromUDP.Port), TCP: uint16(result.TCPPort)},
				ReplyTok:   append([]byte(nil), buf[:macSize]...), // MAC of their Ping
				Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
			}
			pongData, _, _ := encodePacket(priv, pongPacket, replyPong)
			conn.WriteTo(pongData, from) //nolint:errcheck

		case pongPacket:
			// Pong response to our Ping — TCP port not in Pong; caller will use UDP port
		}

		return result, nil
	}
}
