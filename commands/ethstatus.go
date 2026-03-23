package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/peterrobinson/bcnode-analysis/internal/devp2p"
	"github.com/peterrobinson/bcnode-analysis/internal/eth"
)

var ethStatusCmd = &cobra.Command{
	Use:   "eth-status <enode>",
	Short: "Show ETH wire protocol status (network ID, genesis, head, total difficulty)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, err := devp2p.Dial(args[0], timeout)
		if err != nil {
			return err
		}
		defer conn.Close()

		if conn.EthVersion == 0 {
			return fmt.Errorf("node does not support a compatible eth protocol version")
		}

		conn.SetDeadline(time.Now().Add(timeout))

		peer := eth.NewPeer(conn, chainFlag)
		status, err := peer.Status()
		if err != nil {
			return fmt.Errorf("eth status exchange: %w", err)
		}

		fmt.Printf("\n=== ETH Protocol Status ===\n")
		fmt.Printf("  Protocol:     eth/%d\n", status.ProtocolVersion)
		fmt.Printf("  Network ID:   %d (%s)\n", status.NetworkID, networkName(status.NetworkID))
		fmt.Printf("  Genesis:      %s\n", status.Genesis.Hex())
		fmt.Printf("  Head Block:   %s\n", status.Head.Hex())
		fmt.Printf("  Total Diff:   %s\n", status.TD.String())
		fmt.Printf("  Fork ID:      hash=0x%x  next=%d\n", status.ForkID.Hash, status.ForkID.Next)
		fmt.Println()
		return nil
	},
}

func networkName(id uint64) string {
	switch id {
	case 1:
		return "mainnet"
	case 5:
		return "goerli"
	case 11155111:
		return "sepolia"
	case 17000:
		return "holesky"
	default:
		return "unknown"
	}
}

func init() {
	rootCmd.AddCommand(ethStatusCmd)
}
