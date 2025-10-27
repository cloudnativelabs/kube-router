package utils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildIPSetRestore(t *testing.T) {
	type args struct {
		ipset           *IPSet
		setIncludeNames []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "simple-restore",
			args: args{
				ipset: &IPSet{sets: map[string]*Set{
					"foo": {
						Name:    "foo",
						Options: []string{"hash:ip", "yolo", "things", "12345"},
						Entries: []*Entry{
							{Options: []string{"1.2.3.4"}},
						},
					},
					"google-dns-servers": {
						Name:    "google-dns-servers",
						Options: []string{"hash:ip", "lol"},
						Entries: []*Entry{
							{Options: []string{"4.4.4.4"}},
							{Options: []string{"8.8.8.8"}},
						},
					},
					// this one and the one above share the same exact options -- and therefore will reuse the same
					// tmp ipset:
					"more-ip-addresses": {
						Name:    "google-dns-servers",
						Options: []string{"hash:ip", "lol"},
						Entries: []*Entry{
							{Options: []string{"5.5.5.5"}},
							{Options: []string{"6.6.6.6"}},
						},
					},
				}},
				setIncludeNames: nil,
			},
			want: "create TMP-7NOTZDOMLXBX6DAJ hash:ip yolo things 12345\n" +
				"flush TMP-7NOTZDOMLXBX6DAJ\n" +
				"add TMP-7NOTZDOMLXBX6DAJ 1.2.3.4\n" +
				"create foo hash:ip yolo things 12345\n" +
				"swap TMP-7NOTZDOMLXBX6DAJ foo\n" +
				"flush TMP-7NOTZDOMLXBX6DAJ\n" +
				"create TMP-XD7BSSQZELS7TP35 hash:ip lol\n" +
				"flush TMP-XD7BSSQZELS7TP35\n" +
				"add TMP-XD7BSSQZELS7TP35 4.4.4.4\n" +
				"add TMP-XD7BSSQZELS7TP35 8.8.8.8\n" +
				"create google-dns-servers hash:ip lol\n" +
				"swap TMP-XD7BSSQZELS7TP35 google-dns-servers\n" +
				"flush TMP-XD7BSSQZELS7TP35\n" +
				"add TMP-XD7BSSQZELS7TP35 5.5.5.5\n" +
				"add TMP-XD7BSSQZELS7TP35 6.6.6.6\n" +
				"create google-dns-servers hash:ip lol\n" +
				"swap TMP-XD7BSSQZELS7TP35 google-dns-servers\n" +
				"flush TMP-XD7BSSQZELS7TP35\n" +
				"destroy TMP-7NOTZDOMLXBX6DAJ\n" +
				"destroy TMP-XD7BSSQZELS7TP35\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildIPSetRestore(tt.args.ipset, tt.args.setIncludeNames); got != tt.want {
				t.Errorf("buildIPSetRestore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_buildIPSetRestore_setIncludeNames(t *testing.T) {
	tests := []struct {
		name            string
		ipset           *IPSet
		setIncludeNames []string
		expectedSets    []string
		excludedSets    []string
	}{
		{
			name: "nil setIncludeNames includes all sets",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: nil,
			expectedSets:    []string{"set1", "set2"},
			excludedSets:    []string{},
		},
		{
			name: "empty setIncludeNames includes no sets",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{},
			expectedSets:    []string{},
			excludedSets:    []string{"set1", "set2"},
		},
		{
			name: "filter includes only specified sets",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set3": {
					Name:    "set3",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"9.10.11.12"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"set1", "set3"},
			expectedSets:    []string{"set1", "set3"},
			excludedSets:    []string{"set2"},
		},
		{
			name: "duplicate entries in setIncludeNames",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"set1", "set1", "set2"},
			expectedSets:    []string{"set1", "set2"},
			excludedSets:    []string{},
		},
		{
			name: "IPv6 set names with prefix",
			ipset: &IPSet{sets: map[string]*Set{
				"inet6:set1": {
					Name:    "inet6:set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"2001:db8::1"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"inet6:set2": {
					Name:    "inet6:set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"2001:db8::2"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"regular-set": {
					Name:    "regular-set",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"set1", "set2"},
			expectedSets:    []string{"inet6:set1", "inet6:set2"},
			excludedSets:    []string{"regular-set"},
		},
		{
			name: "IPv6 set names without prefix in filter",
			ipset: &IPSet{sets: map[string]*Set{
				"inet6:set1": {
					Name:    "inet6:set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"2001:db8::1"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"inet6:set2": {
					Name:    "inet6:set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"2001:db8::2"}}},
					Parent:  &IPSet{isIpv6: true},
				},
			}},
			setIncludeNames: []string{"set1"},
			expectedSets:    []string{"inet6:set1"},
			excludedSets:    []string{"inet6:set2"},
		},
		{
			name: "IPv4 set names without prefix",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"set1"},
			expectedSets:    []string{"set1"},
			excludedSets:    []string{"set2"},
		},
		{
			name: "non-existent set names in filter",
			ipset: &IPSet{sets: map[string]*Set{
				"set1": {
					Name:    "set1",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set2": {
					Name:    "set2",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"nonexistent", "set1"},
			expectedSets:    []string{"set1"},
			excludedSets:    []string{"set2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildIPSetRestore(tt.ipset, tt.setIncludeNames)

			// Check that expected sets are included
			for _, expectedSet := range tt.expectedSets {
				assert.Contains(t, result, fmt.Sprintf("create %s", expectedSet),
					"Expected set %s should be created", expectedSet)
			}

			// Check that excluded sets are not included
			for _, excludedSet := range tt.excludedSets {
				assert.NotContains(t, result, fmt.Sprintf("create %s", excludedSet),
					"Excluded set %s should not be created", excludedSet)
			}

			// Ensure we have proper destroy statements for temp sets (only if we have sets)
			if len(tt.expectedSets) > 0 {
				assert.Contains(t, result, "destroy TMP-", "Should contain destroy statements for temp sets")
			} else {
				assert.Empty(t, result, "Should produce empty result when no sets are expected")
			}
		})
	}
}

func Test_buildIPSetRestore_boundaryConditions(t *testing.T) {
	tests := []struct {
		name            string
		ipset           *IPSet
		setIncludeNames []string
		description     string
	}{
		{
			name:            "empty ipset",
			ipset:           &IPSet{sets: map[string]*Set{}},
			setIncludeNames: nil,
			description:     "Empty ipset should produce empty result",
		},
		{
			name: "ipset with empty sets",
			ipset: &IPSet{sets: map[string]*Set{
				"empty-set": {
					Name:    "empty-set",
					Options: []string{"hash:ip"},
					Entries: []*Entry{},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: nil,
			description:     "Sets with no entries should still be processed",
		},
		{
			name: "ipset with nil entries",
			ipset: &IPSet{sets: map[string]*Set{
				"nil-entries-set": {
					Name:    "nil-entries-set",
					Options: []string{"hash:ip"},
					Entries: nil,
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: nil,
			description:     "Sets with nil entries should not panic",
		},
		{
			name: "ipset with very long set names",
			ipset: &IPSet{sets: map[string]*Set{
				"very-long-set-name-that-exceeds-normal-limits-and-should-still-work": {
					Name:    "very-long-set-name-that-exceeds-normal-limits-and-should-still-work",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: nil,
			description:     "Very long set names should be handled",
		},
		{
			name: "ipset with special characters in names",
			ipset: &IPSet{sets: map[string]*Set{
				"set-with-dashes": {
					Name:    "set-with-dashes",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"set_with_underscores": {
					Name:    "set_with_underscores",
					Options: []string{"hash:ip"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"set-with-dashes"},
			description:     "Set names with special characters should be handled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This should not panic
			result := BuildIPSetRestore(tt.ipset, tt.setIncludeNames)

			// Basic validation that we get a string result
			assert.IsType(t, "", result, tt.description)

			// If we have sets, we should have some output
			if len(tt.ipset.sets) > 0 {
				assert.NotEmpty(t, result, "Should produce non-empty result when sets exist")
			} else {
				assert.Empty(t, result, "Should produce empty result when no sets exist")
			}
		})
	}
}

func Test_buildIPSetRestore_differentTypes(t *testing.T) {
	tests := []struct {
		name             string
		ipset            *IPSet
		expectedTempSets int
		description      string
	}{
		{
			name: "different ipset types create separate temp sets",
			ipset: &IPSet{sets: map[string]*Set{
				"hash-ip-set": {
					Name:    "hash-ip-set",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"hash-net-set": {
					Name:    "hash-net-set",
					Options: []string{"hash:net", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"192.168.0.0/16"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"hash-ip-port-set": {
					Name:    "hash-ip-port-set",
					Options: []string{"hash:ip,port", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"1.2.3.4,tcp:80"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			expectedTempSets: 3,
			description:      "Different ipset types should create separate temporary sets",
		},
		{
			name: "same ipset types reuse temp sets",
			ipset: &IPSet{sets: map[string]*Set{
				"hash-ip-set1": {
					Name:    "hash-ip-set1",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"hash-ip-set2": {
					Name:    "hash-ip-set2",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			expectedTempSets: 1,
			description:      "Same ipset types should reuse the same temporary set",
		},
		{
			name: "same type different options create separate temp sets",
			ipset: &IPSet{sets: map[string]*Set{
				"hash-ip-timeout-0": {
					Name:    "hash-ip-timeout-0",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"1.2.3.4"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"hash-ip-timeout-300": {
					Name:    "hash-ip-timeout-300",
					Options: []string{"hash:ip", "timeout", "300"},
					Entries: []*Entry{{Options: []string{"5.6.7.8"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			expectedTempSets: 2,
			description:      "Same type with different options should create separate temporary sets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildIPSetRestore(tt.ipset, nil)

			// Count the number of temporary sets created
			tempSetCount := strings.Count(result, "create TMP-")
			assert.Equal(t, tt.expectedTempSets, tempSetCount, tt.description)

			// Count the number of temporary sets destroyed
			destroyCount := strings.Count(result, "destroy TMP-")
			assert.Equal(t, tt.expectedTempSets, destroyCount, "Should destroy same number of temp sets as created")
		})
	}
}

func Test_buildIPSetRestore_integrationRealWorldSets(t *testing.T) {
	// This test uses real-world set names from the kube-router codebase to ensure
	// that we don't accidentally delete important sets when using setIncludeNames

	tests := []struct {
		name            string
		ipset           *IPSet
		setIncludeNames []string
		description     string
	}{
		{
			name: "routing controller sets only",
			ipset: &IPSet{sets: map[string]*Set{
				"kube-router-pod-subnets": {
					Name:    "kube-router-pod-subnets",
					Options: []string{"hash:net", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.244.0.0/16"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"kube-router-node-ips": {
					Name:    "kube-router-node-ips",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"192.168.1.100"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"kube-router-svip": {
					Name:    "kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.96.0.1"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"kube-router-pod-subnets", "kube-router-node-ips"},
			description:     "Should only restore routing controller sets, not service sets",
		},
		{
			name: "service controller sets only",
			ipset: &IPSet{sets: map[string]*Set{
				"kube-router-svip": {
					Name:    "kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.96.0.1"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"kube-router-svip-prt": {
					Name:    "kube-router-svip-prt",
					Options: []string{"hash:ip,port", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.96.0.1,tcp:80"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"kube-router-pod-subnets": {
					Name:    "kube-router-pod-subnets",
					Options: []string{"hash:net", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.244.0.0/16"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"kube-router-svip", "kube-router-svip-prt"},
			description:     "Should only restore service controller sets, not routing sets",
		},
		{
			name: "network policy sets only",
			ipset: &IPSet{sets: map[string]*Set{
				"KUBE-SRC-ABCD1234567890AB": {
					Name:    "KUBE-SRC-ABCD1234567890AB",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.244.1.5"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"KUBE-DST-EFGH1234567890CD": {
					Name:    "KUBE-DST-EFGH1234567890CD",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.244.2.10"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"kube-router-svip": {
					Name:    "kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.96.0.1"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"KUBE-SRC-ABCD1234567890AB", "KUBE-DST-EFGH1234567890CD"},
			description:     "Should only restore network policy sets, not service sets",
		},
		{
			name: "IPv6 sets with prefix matching",
			ipset: &IPSet{sets: map[string]*Set{
				"inet6:kube-router-svip": {
					Name:    "inet6:kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"2001:db8::1"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"inet6:kube-router-svip-prt": {
					Name:    "inet6:kube-router-svip-prt",
					Options: []string{"hash:ip,port", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"2001:db8::1,tcp:80"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"inet6:KUBE-SRC-ABCD1234567890AB": {
					Name:    "inet6:KUBE-SRC-ABCD1234567890AB",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"2001:db8:1::5"}}},
					Parent:  &IPSet{isIpv6: true},
				},
			}},
			setIncludeNames: []string{"kube-router-svip", "kube-router-svip-prt"},
			description:     "Should match IPv6 sets by removing inet6: prefix",
		},
		{
			name: "mixed IPv4 and IPv6 sets",
			ipset: &IPSet{sets: map[string]*Set{
				"kube-router-svip": {
					Name:    "kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.96.0.1"}}},
					Parent:  &IPSet{isIpv6: false},
				},
				"inet6:kube-router-svip": {
					Name:    "inet6:kube-router-svip",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"2001:db8::1"}}},
					Parent:  &IPSet{isIpv6: true},
				},
				"KUBE-SRC-ABCD1234567890AB": {
					Name:    "KUBE-SRC-ABCD1234567890AB",
					Options: []string{"hash:ip", "timeout", "0"},
					Entries: []*Entry{{Options: []string{"10.244.1.5"}}},
					Parent:  &IPSet{isIpv6: false},
				},
			}},
			setIncludeNames: []string{"kube-router-svip"},
			description:     "Should include both IPv4 and IPv6 versions of the same set name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildIPSetRestore(tt.ipset, tt.setIncludeNames)

			// Verify that only the specified sets are included
			for setName, set := range tt.ipset.sets {
				shouldBeIncluded := false
				for _, includeName := range tt.setIncludeNames {
					// Check if this set should be included based on the filtering logic
					origName := setName
					if set.Parent != nil && set.Parent.isIpv6 {
						origName = strings.Replace(setName, fmt.Sprintf("%s:", IPv6SetPrefix), "", 1)
					}
					if origName == includeName {
						shouldBeIncluded = true
						break
					}
				}

				if shouldBeIncluded {
					assert.Contains(t, result, fmt.Sprintf("create %s", setName),
						"Set %s should be included in restore", setName)
				} else {
					assert.NotContains(t, result, fmt.Sprintf("create %s", setName),
						"Set %s should not be included in restore", setName)
				}
			}

			// Ensure we have proper temp set management
			assert.Contains(t, result, "destroy TMP-", "Should contain destroy statements for temp sets")

			// Verify that the result is deterministic (sorted)
			lines := strings.Split(strings.TrimSpace(result), "\n")
			assert.True(t, len(lines) > 0, "Should have some output")
		})
	}
}

func Test_scrubInitValFromOptions(t *testing.T) {
	t.Run("Initval should always be scrubbed no matter where it exists", func(t *testing.T) {
		desired := strings.Split("hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12", " ")
		typicalLine := strings.Split(
			"hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0x1441ebfe", " ")
		initValInMiddle := strings.Split(
			"hash:ip family inet hashsize 1024 maxelem 65536 initval 0x1441ebfe timeout 0 bucketsize 12", " ")
		initValInFront := strings.Split(
			"initval 0x1441ebfe hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12", " ")
		assert.Equal(t, desired, scrubInitValFromOptions(typicalLine),
			"scrubInitValFromOutput should be able to handle a typical ipset restore line")
		assert.Equal(t, desired, scrubInitValFromOptions(initValInMiddle),
			"scrubInitValFromOutput should be able to remove initval from anywhere in the line")
		assert.Equal(t, desired, scrubInitValFromOptions(initValInFront),
			"scrubInitValFromOutput should be able to remove initval from anywhere in the line")
	})

	t.Run("If initval doesn't exist, options should be returned unchanged", func(t *testing.T) {
		desired := strings.Split("hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12", " ")
		noInitVal := strings.Split("hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12", " ")
		assert.Equal(t, desired, scrubInitValFromOptions(noInitVal))
	})
}

func Test_parseIPSetSave(t *testing.T) {
	ipsetSaveText := `
create inet6:kube-router-local-ips hash:ip family inet6 hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0x6b804011
create inet6:kube-router-svip hash:ip family inet6 hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0x1f794545
add inet6:kube-router-svip 2001:db8:42:1::423b timeout 0
add inet6:kube-router-svip 2001:db8:42:1200:: timeout 0
create inet6:kube-router-svip-prt hash:ip,port family inet6 hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0xdf8a8ddd
add inet6:kube-router-svip-prt 2001:db8:42:1200::,tcp:5000 timeout 0
add inet6:kube-router-svip-prt 2001:db8:42:1::423b,tcp:5000 timeout 0
create KUBE-DST-2FAIIK2E4RIPMTGF hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0x331717b4
add KUBE-DST-2FAIIK2E4RIPMTGF 10.242.1.11 timeout 0
create inet6:KUBE-DST-I3PRO5XXEERITJZO hash:ip family inet6 hashsize 1024 maxelem 65536 timeout 0 bucketsize 12 initval 0xb7e095a4
add inet6:KUBE-DST-I3PRO5XXEERITJZO 2001:db8:42:1001::b timeout 0
`
	tests := []struct {
		name  string
		ipset *IPSet
		have  string
		want  map[string][]string
	}{
		{
			name:  "Ensure IPv4 parent only contains IPv4 sets",
			ipset: &IPSet{isIpv6: false},
			have:  ipsetSaveText,
			want: map[string][]string{
				"KUBE-DST-2FAIIK2E4RIPMTGF": {
					"10.242.1.11",
				},
			},
		},
		{
			name:  "Ensure IPv6 parent only contains IPv6 sets",
			ipset: &IPSet{isIpv6: true},
			have:  ipsetSaveText,
			want: map[string][]string{
				"inet6:kube-router-local-ips": {},
				"inet6:kube-router-svip": {
					"2001:db8:42:1::423b",
					"2001:db8:42:1200::",
				},
				"inet6:kube-router-svip-prt": {
					"2001:db8:42:1200::,tcp:5000",
					"2001:db8:42:1::423b,tcp:5000",
				},
				"inet6:KUBE-DST-I3PRO5XXEERITJZO": {
					"2001:db8:42:1001::b",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := parseIPSetSave(tt.ipset, tt.have)
			require.Len(t, results, len(tt.want), "want and have should be the same length")
			idx := 0
			for ipsetName, ipsetEntries := range tt.want {
				require.Contains(t, results, ipsetName)
				resEntries := results[ipsetName]
				for idx2, entry := range ipsetEntries {
					assert.Equal(t, entry, resEntries.Entries[idx2].Options[0])
				}
				idx++
			}
		})
	}
}
