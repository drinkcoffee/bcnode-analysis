package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/peterrobinson/bcnode-analysis/internal/devp2p"
)

var pingCmd = &cobra.Command{
	Use:   "ping <enode>",
	Short: "Test connectivity: perform RLPx handshake + DevP2P hello + ping/pong",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		start := time.Now()

		conn, err := devp2p.Dial(args[0], timeout)
		if err != nil {
			return fmt.Errorf("handshake failed: %w", err)
		}
		defer conn.Close()

		helloRTT := time.Since(start)

		conn.SetDeadline(time.Now().Add(timeout))
		pingStart := time.Now()
		if err := conn.Ping(); err != nil {
			return fmt.Errorf("ping failed: %w", err)
		}
		pingRTT := time.Since(pingStart)

		fmt.Printf("\n=== Ping Results ===\n")
		fmt.Printf("  Handshake RTT: %v\n", helloRTT.Round(time.Millisecond))
		fmt.Printf("  Ping RTT:      %v\n", pingRTT.Round(time.Millisecond))
		fmt.Printf("  Client:        %s\n", conn.TheirHello.Name)
		fmt.Printf("  Status:        OK\n\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}
