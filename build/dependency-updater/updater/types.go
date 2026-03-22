package updater

// Categories controls which dependency categories are processed.
type Categories struct {
	Docker     bool
	Tools      bool
	Actions    bool
	Go         bool
	Dockerfile bool
	Daemonsets bool
}

// All returns a Categories with all standard categories enabled (daemonsets excluded).
func All() Categories {
	return Categories{
		Docker:     true,
		Tools:      true,
		Actions:    true,
		Go:         true,
		Dockerfile: true,
		Daemonsets: false,
	}
}
