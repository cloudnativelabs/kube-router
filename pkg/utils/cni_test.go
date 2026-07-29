package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cniConfTestFileName     = "10-kuberouter.conf"
	cniConfListTestFileName = "10-kuberouter.conflist"
)

type cniConfContent struct {
	name       string
	isConfList bool
	bytes      []byte
}

func (c *cniConfContent) fileName() string {
	if c.isConfList {
		return cniConfListTestFileName
	}
	return cniConfTestFileName
}

func getConfList() cniConfContent {
	return cniConfContent{"confList", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "plugins":[
    {
      "bridge":"kube-bridge",
      "ipam":{
        "subnet":"10.242.0.0/24",
        "type":"host-local"
      },
      "isDefaultGateway":true,
      "mtu":9001,
      "name":"kubernetes",
      "type":"bridge"
    }
  ]
}
`)}
}

func getConfListWithRanges() cniConfContent {
	return cniConfContent{"confListWithRanges", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "plugins":[
    {
      "bridge":"kube-bridge",
      "ipam":{
        "ranges": [
          [
            {
              "subnet":"10.242.0.0/24"
            },
            {
              "subnet":"10.242.1.0/24"
            }
          ],
          [
            {
              "subnet":"10.242.2.0/24"
            },
            {
              "subnet":"10.242.3.0/24"
            }
          ]
        ],
        "subnet": "10.242.4.0/24",
        "type":"host-local"
      },
      "isDefaultGateway":true,
      "mtu":9001,
      "name":"kubernetes",
      "type":"bridge"
    }
  ]
}
`)}
}

func getConfListWithDuplicateRanges() cniConfContent {
	return cniConfContent{"confListWithDuplicateRanges", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "plugins":[
    {
      "bridge":"kube-bridge",
      "ipam":{
        "ranges": [
          [
            {
              "subnet":"10.242.0.0/24"
            },
            {
              "subnet":"10.242.1.0/24"
            }
          ],
          [
            {
              "subnet":"10.242.2.0/24"
            },
            {
              "subnet":"10.242.3.0/24"
            }
          ]
        ],
        "subnet": "10.242.0.0/24",
        "type":"host-local"
      },
      "isDefaultGateway":true,
      "mtu":9001,
      "name":"kubernetes",
      "type":"bridge"
    }
  ]
}
`)}
}

func getConfListWithIPv6DuplicateRanges() cniConfContent {
	return cniConfContent{"confListWithIPv6DuplicateRanges", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "plugins":[
    {
      "bridge":"kube-bridge",
      "ipam":{
        "ranges": [
          [
            {
              "subnet":"10.242.0.0/24"
            },
            {
              "subnet":"10.242.1.0/24"
            }
          ],
          [
            {
              "subnet":"10.242.2.0/24"
            },
            {
              "subnet":"2001:db8:42:2::/64"
            }
          ]
        ],
        "subnet": "2001:db8:42:2::/64",
        "type":"host-local"
      },
      "isDefaultGateway":true,
      "mtu":9001,
      "name":"kubernetes",
      "type":"bridge"
    }
  ]
}
`)}
}

func getConfListWithNoSubnet() cniConfContent {
	return cniConfContent{"confListWithNoSubnet", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "plugins":[
    {
      "bridge":"kube-bridge",
      "ipam":{
        "type":"host-local"
      },
      "isDefaultGateway":true,
      "name":"kubernetes",
      "type":"bridge"
    }
  ]
}
`)}
}

func getConfListWithNoPlugins() cniConfContent {
	return cniConfContent{"confListWithNoPlugins", true, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet"
}`)}
}

func getConf() cniConfContent {
	return cniConfContent{"conf", false, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "bridge":"kube-bridge",
  "ipam":{
	"type":"host-local",
    "subnet": "10.242.0.0/24"
  },
  "isDefaultGateway":true,
  "name":"kubernetes",
  "type":"bridge"
}
`)}
}

func getConfWithNoSubnet() cniConfContent {
	return cniConfContent{"confWithNoSubnet", false, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "bridge":"kube-bridge",
  "ipam":{
    "type":"host-local"
  },
  "isDefaultGateway":true,
  "name":"kubernetes",
  "type":"bridge"
}
`)}
}

func getConfWithNoType() cniConfContent {
	return cniConfContent{"confWithNoType", false, []byte(`{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "bridge":"kube-bridge",
  "ipam":{
    "type":"host-local"
  },
  "isDefaultGateway":true,
  "name":"kubernetes"
}
`)}
}

func allCNIConfContents() []cniConfContent {
	return []cniConfContent{
		getConfList(),
		getConfListWithRanges(),
		getConfListWithDuplicateRanges(),
		getConfListWithIPv6DuplicateRanges(),
		getConfListWithNoSubnet(),
		getConfListWithNoPlugins(),
		getConf(),
		getConfWithNoSubnet(),
		getConfWithNoType(),
	}
}

func TestMarshalUnmarshalRestoration(t *testing.T) {
	for _, content := range allCNIConfContents() {
		t.Run(content.name, func(t *testing.T) {
			t.Parallel()

			var obj any
			if content.isConfList {
				obj = new(ConfList)
			} else {
				obj = new(Conf)
			}

			require.NoError(t, json.Unmarshal(content.bytes, obj))
			after, err := json.Marshal(obj)
			require.NoError(t, err)

			assert.JSONEq(t, string(content.bytes), string(after))
		})
	}
}

func TestNewCNINetworkConfig(t *testing.T) {
	testcases := []struct {
		name    string
		content cniConfContent
		err     error
		ranges  []string
	}{
		{
			name:    "Attempt reading from conf",
			content: getConf(),
			err:     nil,
		},
		{
			name:    "Attempt reading from conflist",
			content: getConfList(),
			err:     nil,
		},
		{
			name:    "Ensure error upon reading from conf with no type",
			content: getConfWithNoType(),
			err:     errors.New("error load CNI config, file appears to have no type: "),
		},
		{
			name:    "Ensure error upon reading from conflist with no plugins",
			content: getConfListWithNoPlugins(),
			err:     errors.New("CNI config list "),
		},
		{
			name:    "Ensure conf subnet get consolidated into ranges when only subnet exists",
			content: getConf(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			content: getConfList(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnets get consolidated with ranges when both exist",
			content: getConfListWithRanges(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithDuplicateRanges(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			if err != nil {
				if testcase.err == nil {
					assert.Fail(t, "if error from NewCNINetworkConfig is not nil, the testcase shouldn't be "+
						"nil either")
				}
				assert.True(t, strings.HasPrefix(err.Error(), testcase.err.Error()))
				return
			}

			if testcase.content.isConfList {
				assert.NotNilf(t, cni.confList, "Expected a conflist for %s", testcase.content.name)
			} else {
				assert.Nilf(t, cni.confList, "Didn't expect a conflist for %s", testcase.content.name)
			}

			if testcase.ranges != nil {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Subnet,
					"subnet of cniNetworkConfig should always be empty because it should be consolidated with "+
						"ranges upon creation")

				foundSubnets := make(map[string]any, 0)
				for _, rangeSet := range cni.getBridgePlugin().IPAM.Ranges {
					for _, rangeSubnet := range rangeSet {
						foundSubnets[rangeSubnet.Subnet] = struct{}{}
					}
				}

				assert.Len(t, foundSubnets, len(testcase.ranges))

				for _, subnet := range testcase.ranges {
					_, found := foundSubnets[subnet]
					assert.Truef(t, found, "subnet %s from testcase should have been found in the ranges inside "+
						"cniNetworkConfig", subnet)
				}
			}
		})
	}
}

func TestCniNetworkConfig_GetPodCIDRsFromCNISpec(t *testing.T) {
	testcases := []struct {
		name    string
		content cniConfContent
		err     error
		ranges  []string
	}{
		{
			name:    "Ensure conf subnet get consolidated into ranges when only subnet exists",
			content: getConf(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			content: getConfList(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnets get consolidated with ranges when both exist",
			content: getConfListWithRanges(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithDuplicateRanges(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithIPv6DuplicateRanges(),
			err:     nil,
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "2001:db8:42:2::/64"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			assert.Equal(t, testcase.err, err)
			if err != nil {
				return
			}

			if testcase.content.isConfList {
				assert.NotNilf(t, cni.confList, "Expected a conflist for %s", testcase.content.name)
			} else {
				assert.Nilf(t, cni.confList, "Didn't expect a conflist for %s", testcase.content.name)
			}

			if testcase.ranges != nil {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Subnet,
					"subnet of cniNetworkConfig should always be empty because it should be consolidated with "+
						"ranges upon creation")

				foundSubnets, err := cni.GetPodCIDRsFromCNISpec()

				assert.Nil(t, err, "err should be nil at this point")

				assert.Len(t, foundSubnets, len(testcase.ranges))

				for _, subnet := range testcase.ranges {
					found := false
					for _, foundSubnet := range foundSubnets {
						if subnet == foundSubnet.String() {
							found = true
						}
					}
					assert.Truef(t, found, "subnet %s from testcase should have been found in the ranges inside "+
						"cniNetworkConfig", subnet)
				}
			}
		})
	}
}

func TestCniNetworkConfig_InsertPodCIDRIntoIPAM(t *testing.T) {
	testcases := []struct {
		name         string
		content      cniConfContent
		err          error
		ranges       []string
		insertRanges []string
	}{
		{
			name:         "Ensure passed CIDR is properly inserted into a CNI conf with no subnets defined",
			content:      getConfWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure multiple CIDRs are properly inserted into a CNI conf with no subnets defined",
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name: "Ensure multiple IPv4 & IPv6 CIDRs are properly inserted into a CNI conf with no subnets" +
				"defined",
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:    "Ensure that new subnets are inserted into a conflist with existing ranges",
			content: getConfListWithRanges(),
			err:     nil,
			ranges: []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24",
				"10.242.5.0/24", "10.242.6.0/24"},
			insertRanges: []string{"10.242.5.0/24", "10.242.6.0/24"},
		},
		{
			name:         "Ensure duplicates are not inserted without error",
			content:      getConfListWithDuplicateRanges(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
			insertRanges: []string{"10.242.4.0/24"},
		},
		{
			name:    "Ensure error is thrown for bad cidr",
			content: getConfListWithDuplicateRanges(),
			err: fmt.Errorf("unable to parse input cidr: %s - %s", "10.242.4.0",
				"invalid CIDR address: 10.242.4.0"),
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
			insertRanges: []string{"10.242.4.0"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			if err != nil {
				assert.Fail(t, "err should always be nil when calling NewCNINetworkConfig for this suite")
			}

			for _, cidr := range testcase.insertRanges {
				err = cni.InsertPodCIDRIntoIPAM(cidr)
				if testcase.err != nil {
					assert.EqualError(t, err, testcase.err.Error())
				} else {
					assert.NoError(t, err)
				}
			}

			expectedSubnets := make([]string, 0)
			netSubnets, _ := cni.GetPodCIDRsFromCNISpec()
			for _, netSubnet := range netSubnets {
				expectedSubnets = append(expectedSubnets, netSubnet.String())
			}
			assert.ElementsMatch(t, testcase.ranges, expectedSubnets)
		})
	}
}

func TestCniNetworkConfig_WriteCNIConfig(t *testing.T) {
	testcases := []struct {
		name         string
		content      cniConfContent
		err          error
		ranges       []string
		insertRanges []string
	}{
		{
			name:    "Ensure written file is the same as read file when no ranges were inserted",
			content: getConfWithNoSubnet(),
			err:     nil,
		},
		{
			name:         "Ensure written conf file contains single subnet",
			content:      getConf(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure written conflist file contains multiple subnets",
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name:         "Ensure written conflist file has IPv4 & IPv6 CIDRs properly inserted",
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:    "Ensure that conflist file has multiple subnets written when ranges already exist",
			content: getConfListWithRanges(),
			err:     nil,
			ranges: []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24",
				"10.242.5.0/24", "10.242.6.0/24"},
			insertRanges: []string{"10.242.5.0/24", "10.242.6.0/24"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			if err != nil {
				assert.Fail(t, "err should always be nil when calling NewCNINetworkConfig for this suite")
			}

			if testcase.insertRanges != nil {
				for _, cidr := range testcase.insertRanges {
					err = cni.InsertPodCIDRIntoIPAM(cidr)
					assert.Equal(t, testcase.err, err)
				}
			}

			err = cni.WriteCNIConfig()
			if err != nil {
				t.Fatalf("Failed to marshal or write CNI file: %v", err)
			}

			// Read the CNI directly to ensure that subnet is really removed (which wouldn't be detected upon
			// re-initialization of NewCNINetworkConfig below because of how it treats subnets
			cniFileBytes, err := os.ReadFile(confFilePath)
			if err != nil {
				t.Fatalf("we should be able to read the CNI file we just wrote to")
			}
			var brPlug *Conf
			if testcase.content.isConfList {
				cl := new(ConfList)
				err = json.Unmarshal(cniFileBytes, cl)
				if err != nil {
					t.Fatalf("wasn't able to unmarshal JSON in test: %s", cniFileBytes)
				}
				for _, plug := range cl.Plugins {
					if plug.Type == "bridge" {
						brPlug = plug
					}
				}
			} else {
				cl := new(Conf)
				err = json.Unmarshal(cniFileBytes, cl)
				if err != nil {
					t.Fatalf("wasn't able to unmarshal JSON in test: %s", cniFileBytes)
				}
				brPlug = cl
			}

			if brPlug == nil {
				t.Fatalf("bridge plugin should be populated by all unit tests")
			}
			assert.Emptyf(t, brPlug.IPAM.Subnet, "upon calling WriteCNIConfig() subnet should ALWAYS be blank "+
				"because it should have been consolidated with ranges")

			cni, err = NewCNINetworkConfig(confFilePath)
			if err != nil {
				assert.Fail(t, "err should always be nil when calling NewCNINetworkConfig for this suite")
			}

			if testcase.ranges != nil {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Subnet,
					"subnet of cniNetworkConfig should always be empty because it should be consolidated with "+
						"ranges upon creation")

				foundSubnets := make(map[string]any, 0)
				for _, rangeSet := range cni.getBridgePlugin().IPAM.Ranges {
					for _, rangeSubnet := range rangeSet {
						foundSubnets[rangeSubnet.Subnet] = struct{}{}
					}
				}

				assert.Len(t, foundSubnets, len(testcase.ranges))

				for _, subnet := range testcase.ranges {
					_, found := foundSubnets[subnet]
					assert.Truef(t, found, "subnet %s from testcase should have been found in the ranges inside "+
						"cniNetworkConfig", subnet)
				}
			} else {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Ranges,
					"testcase ranges was nil, the subnets re-read from the CNI file after writing should have "+
						"been empty also")
			}
		})
	}
}
