package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/peterrobinson/bcnode-analysis/internal/devp2p"
	"github.com/peterrobinson/bcnode-analysis/internal/eth"
)

var (
	headersStart   uint64
	headersCount   uint64
	headersReverse bool
)

var headersCmd = &cobra.Command{
	Use:   "headers <enode>",
	Short: "Fetch block headers from a node",
	Long: `Fetches block headers from an Ethereum node via the eth wire protocol.
Uses the node's current head block as the default starting point.`,
	Args: cobra.ExactArgs(1),
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

		// Exchange status first to get the peer's head block number
		status, err := peer.Status()
		if err != nil {
			return fmt.Errorf("eth status: %w", err)
		}

		fmt.Printf("\n=== Node Head: %s (network=%s) ===\n",
			status.Head.Hex()[:16]+"...", networkName(status.NetworkID))

		start := headersStart
		if !cmd.Flags().Changed("start") {
			// Default: use head hash to fetch the most recent headers
			headers, err := peer.GetHeadersByHash(status.Head, headersCount, 0, true)
			if err != nil {
				return fmt.Errorf("get headers: %w", err)
			}
			printHeaders(headers)
			return nil
		}

		conn.SetDeadline(time.Now().Add(timeout))
		headers, err := peer.GetHeadersByNumber(start, headersCount, 0, headersReverse)
		if err != nil {
			return fmt.Errorf("get headers: %w", err)
		}
		printHeaders(headers)
		return nil
	},
}

func printHeaders(headers []*eth.BlockHeader) {
	fmt.Printf("\n=== Block Headers (%d) ===\n", len(headers))
	for _, h := range headers {
		fmt.Printf("  #%-9d  hash=%s  parent=%s  time=%d  txs=%d  gas=%d/%d\n",
			h.Number,
			shortHash(h.Hash),
			shortHash(h.ParentHash),
			h.Time,
			h.TxCount,
			h.GasUsed,
			h.GasLimit,
		)
	}
	fmt.Println()
}

func shortHash(h string) string {
	if len(h) >= 16 {
		return h[:10] + "..." + h[len(h)-6:]
	}
	return h
}

func init() {
	headersCmd.Flags().Uint64Var(&headersStart, "start", 0, "starting block number (default: node's head)")
	headersCmd.Flags().Uint64Var(&headersCount, "count", 5, "number of headers to fetch")
	headersCmd.Flags().BoolVar(&headersReverse, "reverse", false, "fetch in reverse (older blocks first)")
	rootCmd.AddCommand(headersCmd)
}
