package commands

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

var timeout time.Duration
var chainFlag string

var rootCmd = &cobra.Command{
	Use:   "gnode",
	Short: "Probe Ethereum nodes via the DevP2P wire protocol",
	Long: `gnode connects to Ethereum nodes using the DevP2P/RLPx protocol,
exchanges handshake messages, and queries interesting information.

Nodes are specified by their enode URL:
  enode://<64-byte-pubkey-hex>@<ip>:<port>

Examples:
  gnode info enode://abc123...@1.2.3.4:30303
  gnode eth-status enode://abc123...@1.2.3.4:30303
  gnode headers enode://abc123...@1.2.3.4:30303 --start 19000000 --count 5
  gnode ping enode://abc123...@1.2.3.4:30303`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 15*time.Second, "connection and read timeout")
	rootCmd.PersistentFlags().StringVar(&chainFlag, "chain", "mainnet", "target chain: mainnet, sepolia, holesky, goerli")
}
