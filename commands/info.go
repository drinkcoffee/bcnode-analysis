package commands

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/peterrobinson/bcnode-analysis/internal/devp2p"
)

var infoCmd = &cobra.Command{
	Use:   "info <enode>",
	Short: "Show DevP2P handshake info (client name, capabilities, node ID)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, err := devp2p.Dial(args[0], timeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))

		h := conn.TheirHello

		fmt.Printf("\n=== DevP2P Node Info ===\n")
		fmt.Printf("  Client:       %s\n", h.Name)
		fmt.Printf("  P2P Version:  %d\n", h.Version)
		fmt.Printf("  Listen Port:  %d\n", h.ListenPort)

		if len(h.ID) > 0 {
			pubhex := hex.EncodeToString(h.ID)
			fmt.Printf("  Node Pubkey:  %s...%s\n", pubhex[:16], pubhex[len(pubhex)-16:])
		}

		caps := make([]string, len(h.Caps))
		for i, c := range h.Caps {
			caps[i] = c.String()
		}
		fmt.Printf("  Capabilities: %s\n", strings.Join(caps, ", "))

		if conn.EthVersion > 0 {
			fmt.Printf("\n  Negotiated:   eth/%d\n", conn.EthVersion)
		} else {
			fmt.Printf("\n  Note: no common eth protocol version (peer may not support eth)\n")
		}
		fmt.Println()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
