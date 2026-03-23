# gnode

A command-line tool for probing Ethereum nodes via the **DevP2P/RLPx wire protocol** — the same protocol Geth nodes use to communicate with each other. Unlike tools that use the HTTP JSON-RPC API, `gnode` connects at the P2P layer and speaks the raw Ethereum wire protocol directly.

## How it works

1. **discv4 Ping** — sends a signed UDP packet to the node; recovers its public key from the signature on the response (no prior knowledge of the key needed)
2. **RLPx handshake** — establishes an encrypted ECIES session using the target node's secp256k1 public key (embedded in the enode URL)
3. **DevP2P Hello** — exchanges client identity, protocol capabilities, and node public key
4. **ETH Status** — exchanges chain state: genesis hash, head block, total difficulty, and fork ID
5. **GetBlockHeaders** — requests specific block headers over the wire

## Installation

```bash
git clone https://github.com/peterrobinson/bcnode-analysis
cd bcnode-analysis
go build -o bin/gnode ./cmd
```

Requires Go 1.21+.

## Usage

Most commands take an enode URL as their argument. If you only know the IP
and port, use `discover` first to get the enode URL.

See the bottom of this page for some sample enode addresses.

### Commands

#### `discover` — recover enode URL from IP and port

Sends a discv4 UDP Ping and recovers the node's public key from the
cryptographic signature on its response. No prior knowledge of the key needed.

```bash
./bin/gnode discover 1.2.3.4:30303
```

```
Pinging 1.2.3.4:30303 via discv4 UDP...

=== Discovered Node ===
  Address:    1.2.3.4:30303 (UDP/discv4)
  TCP Port:   30303
  RTT:        18ms
  Node ID:    4a9d3e7f2b1c8a05...9f3e2b1a8c7d4f06

  enode://4a9d3e7f2b1c8a05...9f3e2b1a8c7d4f06@1.2.3.4:30303
```

The `--enode-only` flag makes the output shell-composable:

```bash
# Discover then immediately query — no manual copy-paste
./bin/gnode info $(./bin/gnode discover 1.2.3.4:30303 --enode-only)
./bin/gnode eth-status $(./bin/gnode discover 1.2.3.4:30303 --enode-only)
```

If the TCP P2P port differs from the UDP discovery port, use `--tcp-port`:

```bash
./bin/gnode discover 1.2.3.4:30303 --tcp-port 30304
```

#### `ping` — connectivity test

Performs the full RLPx + DevP2P Hello handshake and measures round-trip time.

```bash
./bin/gnode ping enode://<pubkey>@1.2.3.4:30303
```

```
=== Ping Results ===
  Handshake RTT: 42ms
  Ping RTT:      8ms
  Client:        Geth/v1.13.14-stable/linux-amd64/go1.21.7
  Status:        OK
```

#### `info` — DevP2P handshake info

Shows the client version string, advertised capabilities, and node public key from the DevP2P Hello message.

```bash
./bin/gnode info enode://<pubkey>@1.2.3.4:30303
```

```
=== DevP2P Node Info ===
  Client:       Geth/v1.13.14-stable/linux-amd64/go1.21.7
  P2P Version:  5
  Listen Port:  30303
  Node Pubkey:  4a9d3e7f2b1c8a05...9f3e2b1a8c7d4f06
  Capabilities: eth/68, snap/1

  Negotiated:   eth/68
```

#### `eth-status` — ETH wire protocol status

Exchanges ETH Status messages and shows the node's chain state.

```bash
./bin/gnode eth-status enode://<pubkey>@1.2.3.4:30303
```

```
=== ETH Protocol Status ===
  Protocol:     eth/68
  Network ID:   1 (mainnet)
  Genesis:      0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
  Head Block:   0x3a4e1e2f9c7b8d05a1f3c2e4b6d8f0a2...
  Total Diff:   58750003716598352816469
  Fork ID:      hash=0x9f3d2254  next=0
```

The fork ID identifies which hard forks the node has applied — useful for detecting chain splits or misconfigured nodes.

#### `headers` — fetch block headers

Fetches block headers via the ETH wire protocol. Defaults to fetching the 5 most recent headers from the node's current head.

```bash
# Fetch headers from the node's current head
./bin/gnode headers enode://<pubkey>@1.2.3.4:30303

# Fetch 10 headers starting at block 20000000
./bin/gnode headers enode://<pubkey>@1.2.3.4:30303 --start 20000000 --count 10
```

```
=== Node Head: 0x3a4e1e2f9c7b8d05... (network=mainnet) ===

=== Block Headers (5) ===
  #20834521    hash=0x3a4e1e2f9c...8d05  parent=0x9f3e2b1a8c...4f06  time=1720000123  txs=-1  gas=14982341/30000000
  #20834520    hash=0x9f3e2b1a8c...4f06  parent=0x2b1c8a054a...3e7f  time=1720000111  txs=-1  gas=12847293/30000000
  ...
```

Note: block headers don't carry a transaction count directly; `-1` means the block contains transactions (its tx trie root is non-empty), `0` means the block is empty.

### Global flags

| Flag | Default | Description |
|---|---|---|
| `--chain` | `mainnet` | Target chain: `mainnet`, `sepolia`, `holesky`, `goerli` |
| `--timeout` | `15s` | Connection and read timeout |

### Examples

```bash
# Full workflow from just an IP and port
./bin/gnode discover 1.2.3.4:30303
./bin/gnode info $(./bin/gnode discover 1.2.3.4:30303 --enode-only)
./bin/gnode eth-status $(./bin/gnode discover 1.2.3.4:30303 --enode-only)
./bin/gnode headers $(./bin/gnode discover 1.2.3.4:30303 --enode-only)

# Test a Sepolia testnet node
./bin/gnode eth-status enode://<pubkey>@1.2.3.4:30303 --chain sepolia

# Increase timeout for slow nodes
./bin/gnode headers enode://<pubkey>@1.2.3.4:30303 --timeout 30s --count 20

# Fetch blocks in reverse order (newest to oldest)
./bin/gnode headers enode://<pubkey>@1.2.3.4:30303 --start 20000000 --count 10 --reverse
```

## Finding nodes to probe

**If you only have an IP and port** — use `discover`:
```bash
./bin/gnode discover 1.2.3.4:30303
```

**From a running Geth node:**
```bash
geth attach --exec admin.nodeInfo.enode        # this node's own enode
geth attach --exec 'admin.peers.map(p => p.enode)'  # connected peers
```

**From Geth's public bootnode list** (mainnet):
```
enode://d860a01f9722d78051619d1e2351aea3cc926165a4a2b1fec560ea1ec7ca03d3c97b08695c43e9af51a7c97d59414a9cce86d78b4fa3b0e1e9f12ead9c66f7a4e@18.138.108.67:30303
enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c69f9b5668b627a4e93b2b5f13b9f3@3.209.45.79:30303
```

## Protocol notes

- `gnode` uses an ephemeral key pair for each connection — it doesn't present a persistent node identity
- `discover` uses UDP (discv4); all other commands use TCP (RLPx). Make sure both ports are reachable if they differ
- The ETH `Status` message exchange may cause the remote node to disconnect if the fork ID doesn't match (e.g. connecting to a Sepolia node without `--chain sepolia`). The `eth-status` command still succeeds because the remote node sends its Status before validating ours
- `headers` requires the Status exchange to succeed without a disconnect, so use the correct `--chain` flag when connecting to non-mainnet nodes


## Enode Addresses

Immutable zkEVM chain:

```
enode://55b31c45e8c1dbd3e6f551dc9b5ade80eed38e754f033348bd479d98b1db1aee298d93af5c0992f50a7c5cdb686790ade04c584018b2634da193bc8c42d72209@partner-public-0.p2p.immutable.com:30300
enode://2f421178a1b51a1bf9b10dc7e7a0e7cb64446e11b5c9a6bf9697fe619918f3835435833d5df7354d3e43382748fe29f5da3e4e7242fa58fa45af493c421e0cda@partner-public-1.p2p.immutable.com:30300
enode://7864b41535dbbaa31edc4db45157ec8967ac1f9fcea39b4ad17d4506f0618e38f339a2717b39c3d1198dec0154316c6a05408267eeb4d5d8973c6966a21dac90@partner-public-2.p2p.immutable.com:30300
```