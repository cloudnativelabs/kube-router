package utils

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
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

func getNullConfList() cniConfContent {
	return cniConfContent{"nullConfList", true, []byte(`null`)}
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

func getConfListWithNullPlugin() cniConfContent {
	return cniConfContent{"getConfListWithNullPlugin", true, []byte(`{
  "cniVersion": "1.1.0",
  "name":"mynet",
  "plugins":[null]
}`)}
}

func getConfListWithoutBridgePlugin() cniConfContent {
	return cniConfContent{"confListWithoutBridgePlugin", true, []byte(`{
  "cniVersion": "1.1.0",
  "name":"mynet",
  "plugins":[
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
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
		getNullConfList(),
		getConfList(),
		getConfListWithRanges(),
		getConfListWithDuplicateRanges(),
		getConfListWithIPv6DuplicateRanges(),
		getConfListWithNoSubnet(),
		getConfListWithNoPlugins(),
		getConfListWithNullPlugin(),
		getConfListWithoutBridgePlugin(),
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
		err     string
		ranges  []string
	}{
		{
			name:    "Attempt reading from conf",
			content: getConf(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Rejects null conflists",
			content: getNullConfList(),
			err:     "10-kuberouter.conflist has no bridge plugin",
		},
		{
			name:    "Attempt reading from conflist",
			content: getConfList(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure error upon reading from conf with no type",
			content: getConfWithNoType(),
			err:     "10-kuberouter.conf has no type",
		},
		{
			name:    "Ensure error upon reading from conflist with no plugins",
			content: getConfListWithNoPlugins(),
			err:     "10-kuberouter.conflist has no bridge plugin",
		},
		{
			name:    "Ensure conf subnet get consolidated into ranges when only subnet exists",
			content: getConf(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			content: getConfList(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnets get consolidated with ranges when both exist",
			content: getConfListWithRanges(),
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithDuplicateRanges(),
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
		{
			name:    "Doesn't panic on conflists with null plugins",
			content: getConfListWithNullPlugin(),
			err:     "10-kuberouter.conflist has no bridge plugin",
		},
		{
			name:    "Rejects conflists without bridge plugin",
			content: getConfListWithoutBridgePlugin(),
			err:     "10-kuberouter.conflist has no bridge plugin",
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			if testcase.err != "" {
				assert.Nil(t, cni)
				assert.ErrorContains(t, err, testcase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cni)

			if testcase.content.isConfList {
				assert.NotNilf(t, cni.confList, "Expected a conflist for %s", testcase.content.name)
			} else {
				assert.Nilf(t, cni.confList, "Didn't expect a conflist for %s", testcase.content.name)
			}

			podCIDRs, err := cni.getPodCIDRsMapFromCNISpec()
			require.NoError(t, err)
			assert.ElementsMatch(t, testcase.ranges, slices.Collect(maps.Keys(podCIDRs)))
		})
	}
}

func TestCniNetworkConfig_GetPodCIDRsFromCNISpec(t *testing.T) {
	testcases := []struct {
		name    string
		content cniConfContent
		ranges  []string
	}{
		{
			name:    "Ensure conf subnet get consolidated into ranges when only subnet exists",
			content: getConf(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			content: getConfList(),
			ranges:  []string{"10.242.0.0/24"},
		},
		{
			name:    "Ensure conflist subnets get consolidated with ranges when both exist",
			content: getConfListWithRanges(),
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithDuplicateRanges(),
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
		{
			name:    "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			content: getConfListWithIPv6DuplicateRanges(),
			ranges:  []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "2001:db8:42:2::/64"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			confFilePath := filepath.Join(t.TempDir(), testcase.content.fileName())
			require.NoError(t, os.WriteFile(confFilePath, testcase.content.bytes, 0600))

			cni, err := NewCNINetworkConfig(confFilePath)
			require.NoError(t, err)
			require.NotNil(t, cni)

			if testcase.content.isConfList {
				assert.NotNilf(t, cni.confList, "Expected a conflist for %s", testcase.content.name)
			} else {
				assert.Nilf(t, cni.confList, "Didn't expect a conflist for %s", testcase.content.name)
			}

			podCIDRs, err := cni.getPodCIDRsMapFromCNISpec()
			require.NoError(t, err)
			assert.ElementsMatch(t, testcase.ranges, slices.Collect(maps.Keys(podCIDRs)))
		})
	}
}

func TestCniNetworkConfig_InsertPodCIDRIntoIPAM(t *testing.T) {
	testcases := []struct {
		name         string
		content      cniConfContent
		err          string
		ranges       []string
		insertRanges []string
	}{
		{
			name:         "Ensure passed CIDR is properly inserted into a CNI conf with no subnets defined",
			content:      getConfWithNoSubnet(),
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure multiple CIDRs are properly inserted into a CNI conf with no subnets defined",
			content:      getConfListWithNoSubnet(),
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name: "Ensure multiple IPv4 & IPv6 CIDRs are properly inserted into a CNI conf with no subnets" +
				"defined",
			content:      getConfListWithNoSubnet(),
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:    "Ensure that new subnets are inserted into a conflist with existing ranges",
			content: getConfListWithRanges(),
			ranges: []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24",
				"10.242.5.0/24", "10.242.6.0/24"},
			insertRanges: []string{"10.242.5.0/24", "10.242.6.0/24"},
		},
		{
			name:         "Ensure duplicates are not inserted without error",
			content:      getConfListWithDuplicateRanges(),
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
			insertRanges: []string{"10.242.4.0/24"},
		},
		{
			name:    "Ensure error is thrown for bad cidr",
			content: getConfListWithDuplicateRanges(),
			err: fmt.Sprintf("unable to parse input cidr: %s - %s", "10.242.4.0",
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
				if testcase.err != "" {
					assert.EqualError(t, err, testcase.err)
				} else {
					assert.NoErrorf(t, err, "While inserting %s", cidr)
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
		ranges       []string
		insertRanges []string
	}{
		{
			name:    "Ensure written file is the same as read file when no ranges were inserted",
			content: getConfWithNoSubnet(),
		},
		{
			name:         "Ensure written conf file contains single subnet",
			content:      getConf(),
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure written conflist file contains multiple subnets",
			content:      getConfListWithNoSubnet(),
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name:         "Ensure written conflist file has IPv4 & IPv6 CIDRs properly inserted",
			content:      getConfListWithNoSubnet(),
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:    "Ensure that conflist file has multiple subnets written when ranges already exist",
			content: getConfListWithRanges(),
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
					err := cni.InsertPodCIDRIntoIPAM(cidr)
					require.NoError(t, err)
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
			require.NoError(t, err)
			require.NotNil(t, cni)

			podCIDRs, err := cni.getPodCIDRsMapFromCNISpec()
			require.NoError(t, err)
			assert.ElementsMatch(t, testcase.ranges, slices.Collect(maps.Keys(podCIDRs)))
		})
	}
}

func TestNewCNINetworkConfig_Template(t *testing.T) {
	t.Run("Ensure template is parsed according to the CNI conf file name", func(t *testing.T) {
		tmpDir := t.TempDir()
		templateFilePath := filepath.Join(tmpDir, "cni-conf.json")
		require.NoError(t, os.WriteFile(templateFilePath, getConfList().bytes, 0600))

		cni, err := NewCNINetworkConfigFromTemplate(filepath.Join(tmpDir, cniConfListTestFileName), templateFilePath)
		require.NoError(t, err)
		require.NotNil(t, cni)

		assert.NotNil(t, cni.confList, "The CNI conf file name, not the template file name, should determine "+
			"if the config is a conflist")
	})

	t.Run("Ensure CNI conf file is written from the template", func(t *testing.T) {
		tmpDir := t.TempDir()
		templateFilePath := filepath.Join(tmpDir, "cni-conf.json")
		require.NoError(t, os.WriteFile(templateFilePath, getConfListWithNoSubnet().bytes, 0600))
		templateFileInfo, err := os.Stat(templateFilePath)
		require.NoError(t, err)

		cniConfFilePath := filepath.Join(tmpDir, cniConfListTestFileName)
		cni, err := NewCNINetworkConfigFromTemplate(cniConfFilePath, templateFilePath)
		require.NoError(t, err)
		require.NotNil(t, cni)

		require.NoError(t, cni.InsertPodCIDRIntoIPAM("10.242.0.0/24"))
		require.NoError(t, cni.WriteCNIConfig())

		writtenCNI, err := NewCNINetworkConfig(cniConfFilePath)
		require.NoError(t, err)
		require.NotNil(t, writtenCNI)

		podCIDRs, err := writtenCNI.getPodCIDRsMapFromCNISpec()
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"10.242.0.0/24"}, slices.Collect(maps.Keys(podCIDRs)))

		if newTemplateFileInfo, err := os.Stat(templateFilePath); assert.NoError(t, err) {
			assert.True(t, templateFileInfo.Size() == newTemplateFileInfo.Size() &&
				templateFileInfo.ModTime().Equal(newTemplateFileInfo.ModTime()),
				"The template file should remain untouched")
		}

		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		assert.Lenf(t, entries, 2, "No other files besides the template and the CNI conf file should be left "+
			"behind in the CNI conf dir")
	})

	t.Run("Ensure a missing template file is an error", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := NewCNINetworkConfigFromTemplate(
			filepath.Join(tmpDir, cniConfListTestFileName), filepath.Join(tmpDir, "cni-conf.json"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}
