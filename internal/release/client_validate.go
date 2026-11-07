package release

// ValidateClientNode checks only client protocol settings and credentials.
// A synthetic relay destination selects the existing client-only validation
// rules. It is never stored, resolved, dialled or rendered into configuration.
func ValidateClientNode(n Node) error {
	n.RelayAddress = "8.8.8.8"
	n.RelayPort = 443
	return n.validateProtocol()
}

// ValidateNodeConfiguration validates server/client protocol parameters before saving.
func ValidateNodeConfiguration(n Node) error { return n.validateProtocol() }
