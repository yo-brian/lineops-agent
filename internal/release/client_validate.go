package release

import "errors"

// ValidateClientNode checks only client protocol settings and credentials without
// treating the node as a pure TCP relay entry.
func ValidateClientNode(n Node) error {
	if n.RelayAddress != "" || n.RelayPort != 0 {
		return errors.New("external client node cannot include TCP relay parameters")
	}
	return n.validateProtocolMode(true)
}

// ValidateNodeConfiguration validates server/client protocol parameters before saving.
func ValidateNodeConfiguration(n Node) error { return n.validateProtocol() }
