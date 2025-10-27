package testhelpers

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

const tmpIPSetPrefix = "TMP-"

type setState struct {
	setType       string
	entries       [][]string
	createOptions []string
}

// FakeIPSetHandler captures ipset operations for tests.
type FakeIPSetHandler struct {
	lock     sync.Mutex
	isIPv6   bool
	sets     map[string]*setState
	restored string
}

// NewFakeIPSetHandler returns a fake utils.IPSetHandler for the requested IP family.
func NewFakeIPSetHandler(isIPv6 bool) *FakeIPSetHandler {
	return &FakeIPSetHandler{isIPv6: isIPv6, sets: make(map[string]*setState)}
}

func (h *FakeIPSetHandler) normalized(name string) string {
	return utils.IPSetName(name, h.isIPv6)
}

func (h *FakeIPSetHandler) ensure(name string) *setState {
	if state, ok := h.sets[name]; ok {
		return state
	}
	state := &setState{}
	h.sets[name] = state
	return state
}

// Create records the set options.
func (h *FakeIPSetHandler) Create(setName string, createOptions ...string) (*utils.Set, error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	name := h.normalized(setName)
	state := h.ensure(name)
	state.createOptions = append([]string(nil), createOptions...)
	if len(createOptions) > 0 {
		state.setType = createOptions[0]
	}
	return &utils.Set{Name: name, Options: append([]string(nil), state.createOptions...)}, nil
}

// Add is part of the utils.IPSetHandler interface.
func (h *FakeIPSetHandler) Add(_ *utils.Set) error { return nil }

// RefreshSet records entries for the given set.
func (h *FakeIPSetHandler) RefreshSet(setName string, entriesWithOptions [][]string, setType string) {
	h.lock.Lock()
	defer h.lock.Unlock()
	name := h.normalized(setName)
	state := h.ensure(name)
	opts := []string{setType, utils.OptionTimeout, "0"}
	if h.isIPv6 {
		opts = append(opts, "family", "inet6")
	}
	state.createOptions = append([]string(nil), opts...)
	state.setType = setType
	state.entries = make([][]string, len(entriesWithOptions))
	for i, entry := range entriesWithOptions {
		state.entries[i] = append([]string(nil), entry...)
	}
}

// Destroy removes the set.
func (h *FakeIPSetHandler) Destroy(setName string) error {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sets, h.normalized(setName))
	return nil
}

// DestroyAllWithin resets tracked sets.
func (h *FakeIPSetHandler) DestroyAllWithin() error {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.sets = make(map[string]*setState)
	return nil
}

// Save is a no-op for the fake handler.
func (h *FakeIPSetHandler) Save() error { return nil }

// Restore builds and records the restore script.
func (h *FakeIPSetHandler) Restore() error {
	ipsets := h.snapshotSets()
	h.restored = utils.BuildIPSetRestoreFromSets(ipsets, h.isIPv6, nil)
	return nil
}

// RestoreSets builds and records the restore script for the provided sets.
func (h *FakeIPSetHandler) RestoreSets(names []string) error {
	ipsets := h.snapshotSets()
	h.restored = utils.BuildIPSetRestoreFromSets(ipsets, h.isIPv6, names)
	return nil
}

// Flush is a no-op for the fake handler.
func (h *FakeIPSetHandler) Flush() error { return nil }

// Get returns metadata for a tracked set.
func (h *FakeIPSetHandler) Get(setName string) *utils.Set {
	h.lock.Lock()
	defer h.lock.Unlock()
	state, ok := h.sets[h.normalized(setName)]
	if !ok {
		return nil
	}
	return &utils.Set{Name: h.normalized(setName), Options: append([]string(nil), state.createOptions...)}
}

// Sets returns all tracked sets.
func (h *FakeIPSetHandler) Sets() map[string]*utils.Set {
	h.lock.Lock()
	defer h.lock.Unlock()
	res := make(map[string]*utils.Set, len(h.sets))
	for name, state := range h.sets {
		res[name] = &utils.Set{Name: name, Options: append([]string(nil), state.createOptions...)}
	}
	return res
}

// Name normalizes a set name for the family.
func (h *FakeIPSetHandler) Name(name string) string {
	return h.normalized(name)
}

// Restored returns the last restore script that was generated.
func (h *FakeIPSetHandler) Restored() string {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.restored
}

func (h *FakeIPSetHandler) snapshotSets() map[string]*utils.Set {
	result := make(map[string]*utils.Set, len(h.sets))
	for name, state := range h.sets {
		entries := make([]*utils.Entry, len(state.entries))
		for i, entryOpts := range state.entries {
			entries[i] = &utils.Entry{Options: append([]string(nil), entryOpts...)}
		}
		result[name] = &utils.Set{
			Name:    name,
			Options: append([]string(nil), state.createOptions...),
			Entries: entries,
		}
	}
	return result
}

// Snapshot returns a normalized set expectation map useful for assertions.
func (h *FakeIPSetHandler) Snapshot() map[string]IPSetExpectation {
	h.lock.Lock()
	defer h.lock.Unlock()
	res := make(map[string]IPSetExpectation, len(h.sets))
	for name, state := range h.sets {
		entries := make([]string, len(state.entries))
		for i, entry := range state.entries {
			entries[i] = NormalizeSnapshotEntry(strings.Join(entry, " "))
		}
		sort.Strings(entries)
		res[name] = IPSetExpectation{SetType: state.setType, Entries: entries}
	}
	return res
}

// IPSetExpectation captures a set type and sorted entries for comparisons.
type IPSetExpectation struct {
	SetType string
	Entries []string
}

// LoadPodList reads a PodList fixture.
func LoadPodList(t *testing.T, path string) *v1.PodList {
	t.Helper()
	var pods v1.PodList
	loadYAML(t, path, &pods)
	return &pods
}

// LoadNetworkPolicyList reads a NetworkPolicyList fixture.
func LoadNetworkPolicyList(t *testing.T, path string) *networkingv1.NetworkPolicyList {
	t.Helper()
	var list networkingv1.NetworkPolicyList
	loadYAML(t, path, &list)
	return &list
}

// LoadNodeList reads a NodeList fixture.
func LoadNodeList(t *testing.T, path string) *v1.NodeList {
	t.Helper()
	var list v1.NodeList
	loadYAML(t, path, &list)
	return &list
}

// LoadServiceList reads a ServiceList fixture.
func LoadServiceList(t *testing.T, path string) *v1.ServiceList {
	t.Helper()
	var list v1.ServiceList
	loadYAML(t, path, &list)
	return &list
}

func loadYAML(t *testing.T, path string, obj interface{}) {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(content, obj); err != nil {
		t.Fatalf("failed to unmarshal %s: %v", path, err)
	}
}

// ParseSnapshot parses an ipset save snapshot focusing on kube-router managed sets.
func ParseSnapshot(t *testing.T, path string) map[string]IPSetExpectation {
	return ParseSnapshotWithFilter(t, path, func(name string) bool {
		return strings.Contains(name, "KUBE-")
	})
}

// ParseSnapshotWithFilter parses an ipset snapshot and retains set names that satisfy includeFn.
func ParseSnapshotWithFilter(t *testing.T, path string, includeFn func(string) bool) map[string]IPSetExpectation {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("failed to read snapshot %s: %v", path, err)
	}
	lines := strings.Split(string(content), "\n")
	result := make(map[string]IPSetExpectation)
	var current string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "create":
			name := fields[1]
			if includeFn(name) {
				result[name] = IPSetExpectation{SetType: fields[2]}
				current = name
			} else {
				current = ""
			}
		case "add":
			if current == "" {
				continue
			}
			set := result[fields[1]]
			entry := NormalizeSnapshotEntry(strings.Join(fields[2:], " "))
			set.Entries = append(set.Entries, entry)
			result[fields[1]] = set
		}
	}
	for name, exp := range result {
		sort.Strings(exp.Entries)
		if exp.Entries == nil {
			exp.Entries = []string{}
		}
		result[name] = exp
	}
	return result
}

// NormalizeSnapshotEntry normalizes entries for stable comparisons.
func NormalizeSnapshotEntry(entry string) string {
	parts := strings.Split(entry, " ")
	if len(parts) == 3 {
		if strings.Contains(parts[0], "/") {
			parts[0] = strings.Split(parts[0], "/")[0]
		}
	}
	return strings.Join(parts, " ")
}

// ParseRestoreScript parses an ipset restore script into expectations.
func ParseRestoreScript(script string) map[string]IPSetExpectation {
	result := make(map[string]IPSetExpectation)
	tmpEntries := make(map[string][]string)
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "create":
			if len(fields) < 3 {
				continue
			}
			name := fields[1]
			if strings.HasPrefix(name, tmpIPSetPrefix) {
				continue
			}
			setType := fields[2]
			if _, ok := result[name]; !ok {
				result[name] = IPSetExpectation{SetType: setType}
			}
		case "add":
			if len(fields) < 3 {
				continue
			}
			name := fields[1]
			entry := NormalizeSnapshotEntry(strings.Join(fields[2:], " "))
			if strings.HasPrefix(name, tmpIPSetPrefix) {
				tmpEntries[name] = append(tmpEntries[name], entry)
				continue
			}
			set := result[name]
			set.Entries = append(set.Entries, entry)
			result[name] = set
		case "swap":
			if len(fields) < 3 {
				continue
			}
			src, dst := fields[1], fields[2]
			if entries, ok := tmpEntries[src]; ok {
				set := result[dst]
				set.Entries = append([]string(nil), entries...)
				result[dst] = set
				delete(tmpEntries, src)
			}
		case "flush":
			if len(fields) < 2 {
				continue
			}
			if strings.HasPrefix(fields[1], tmpIPSetPrefix) {
				delete(tmpEntries, fields[1])
			}
		}
	}
	for name, exp := range result {
		seen := make(map[string]struct{}, len(exp.Entries))
		deduped := make([]string, 0, len(exp.Entries))
		for _, entry := range exp.Entries {
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			deduped = append(deduped, entry)
		}
		sort.Strings(deduped)
		exp.Entries = deduped
		result[name] = exp
	}
	return result
}

// MergeExpectations merges multiple expectation maps.
func MergeExpectations(maps ...map[string]IPSetExpectation) map[string]IPSetExpectation {
	merged := make(map[string]IPSetExpectation)
	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

// ExpectedKeys returns the sorted keys of an expectation map.
func ExpectedKeys(m map[string]IPSetExpectation) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
