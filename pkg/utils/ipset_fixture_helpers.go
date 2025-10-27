package utils

// BuildIPSetRestoreFromSets returns the restore script for a provided map of sets and an optional filter list.
func BuildIPSetRestoreFromSets(sets map[string]*Set, isIPv6 bool, setNames []string) string {
	ipset := &IPSet{
		sets:   make(map[string]*Set, len(sets)),
		isIpv6: isIPv6,
	}
	for name, set := range sets {
		clone := &Set{
			Parent:  ipset,
			Name:    set.Name,
			Options: append([]string(nil), set.Options...),
		}
		clone.Entries = make([]*Entry, len(set.Entries))
		for i, entry := range set.Entries {
			clone.Entries[i] = &Entry{
				Set:     clone,
				Options: append([]string(nil), entry.Options...),
			}
		}
		ipset.sets[name] = clone
	}
	var include []string
	if setNames != nil {
		include = append([]string(nil), setNames...)
	}
	return BuildIPSetRestore(ipset, include)
}
