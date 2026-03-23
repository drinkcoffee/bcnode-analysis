package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/peterrobinson/bcnode-analysis/internal/discv4"
)

var tcpPortOverride int

var discoverCmd = &cobra.Command{
	Use:   "discover <host:port>",
	Short: "Discover a node's enode URL from its IP address and UDP port",
	Long: `Sends a discv4 UDP Ping to the target and recovers its enode URL.

The node's public key is extracted from the cryptographic signature on its
Ping or Pong response — no prior knowledge of the key is needed.

The UDP discovery port and TCP P2P port are usually the same (default 30303).
If they differ, use --tcp-port to set the TCP port in the output enode URL.

The resulting enode URL can be used with all other gnode commands:

  gnode discover 1.2.3.4:30303
  gnode info $(gnode discover 1.2.3.4:30303 --enode-only)`,
	Args: cobra.ExactArgs(1),
	RunE: discoverRun,
}

var enodeOnly bool

func discoverRun(cmd *cobra.Command, args []string) error {
	host, portStr, err := net.SplitHostPort(args[0])
	if err != nil {
		return fmt.Errorf("invalid address (want host:port): %w", err)
	}
	udpPort, err := strconv.Atoi(portStr)
	if err != nil || udpPort < 1 || udpPort > 65535 {
		return fmt.Errorf("invalid port %q", portStr)
	}

	// Resolve hostname to IP
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	targetIP := net.ParseIP(ips[0])
	if v4 := targetIP.To4(); v4 != nil {
		targetIP = v4
	}

	targetAddr := &net.UDPAddr{IP: targetIP, Port: udpPort}

	if !enodeOnly {
		fmt.Fprintf(cmd.OutOrStdout(), "Pinging %s via discv4 UDP...\n", targetAddr)
	}

	start := time.Now()
	result, err := discv4.Ping(targetAddr, timeout)
	if err != nil {
		return err
	}
	rtt := time.Since(start)

	// Determine TCP port for the enode URL
	tcpPort := udpPort // default: same as UDP
	if result.TCPPort != 0 {
		tcpPort = result.TCPPort
	}
	if tcpPortOverride > 0 {
		tcpPort = tcpPortOverride
	}

	// Build enode URL: enode://<64-byte-hex-pubkey>@<ip>:<tcp-port>
	pubBytes := crypto.FromECDSAPub(result.PubKey) // 65 bytes: 0x04 + X + Y
	nodeIDHex := hex.EncodeToString(pubBytes[1:])   // strip the 0x04 prefix → 64 bytes
	enodeURL := fmt.Sprintf("enode://%s@%s:%d", nodeIDHex, targetIP.String(), tcpPort)

	if enodeOnly {
		fmt.Println(enodeURL)
		return nil
	}

	fmt.Printf("\n=== Discovered Node ===\n")
	fmt.Printf("  Address:    %s:%d (UDP/discv4)\n", targetIP.String(), udpPort)
	fmt.Printf("  TCP Port:   %d\n", tcpPort)
	fmt.Printf("  RTT:        %v\n", rtt.Round(time.Millisecond))
	fmt.Printf("  Node ID:    %s...%s\n", nodeIDHex[:16], nodeIDHex[len(nodeIDHex)-16:])
	fmt.Printf("\n  %s\n\n", enodeURL)

	return nil
}

func init() {
	discoverCmd.Flags().IntVar(&tcpPortOverride, "tcp-port", 0, "override TCP port in the enode URL (default: same as UDP port)")
	discoverCmd.Flags().BoolVar(&enodeOnly, "enode-only", false, "print only the enode URL (useful for shell composition)")
	rootCmd.AddCommand(discoverCmd)
}
