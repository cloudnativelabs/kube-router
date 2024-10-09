package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getConfList() []byte {
	return []byte(`
{
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
`)
}

func getConfListWithRanges() []byte {
	return []byte(`
{
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
`)
}

func getConfListWithDuplicateRanges() []byte {
	return []byte(`
{
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
`)
}

func getConfListWithIPv6DuplicateRanges() []byte {
	return []byte(`
{
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
`)
}

func getConfListWithNoSubnet() []byte {
	return []byte(`
{
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
`)
}

func getConfListWithNoPlugins() []byte {
	return []byte(`
{
  "cniVersion":"0.3.0",
  "name":"mynet"
}
`)
}

func getConf() []byte {
	return []byte(`
{
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
`)
}

func getConfWithNoSubnet() []byte {
	return []byte(`
{
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
`)
}

func getConfWithNoType() []byte {
	return []byte(`
{
  "cniVersion":"0.3.0",
  "name":"mynet",
  "bridge":"kube-bridge",
  "ipam":{
	"type":"host-local"
  },
  "isDefaultGateway":true,
  "name":"kubernetes"
}
`)
}

func TestMarshalUnmarshalRestoration(t *testing.T) {
	t.Run("Ensure ConfList is parsed and unparsed properly", func(t *testing.T) {
		before := getConfList()
		cl := new(ConfList)

		err := json.Unmarshal(before, cl)
		if err != nil {
			t.Fatalf("wasn't able to unmarshal JSON in test: %s", before)
		}

		after, err := json.MarshalIndent(cl, "", "  ")
		if err != nil {
			t.Fatalf("wasn't able to marshal JSON in test: %s", before)
		}

		assert.JSONEqf(t, string(before), string(after),
			"JSON is not equal!\nBefore:\n%s\nAfter:\n%s\n", before, after)
	})
	t.Run("Ensure ConfListWithRange is parsed and unparsed properly", func(t *testing.T) {
		before := getConfListWithRanges()
		cl := new(ConfList)

		err := json.Unmarshal(before, cl)
		if err != nil {
			t.Fatalf("wasn't able to unmarshal JSON in test: %s", before)
		}

		after, err := json.MarshalIndent(cl, "", "  ")
		if err != nil {
			t.Fatalf("wasn't able to marshal JSON in test: %s", before)
		}

		assert.JSONEqf(t, string(before), string(after),
			"JSON is not equal!\nBefore:\n%s\nAfter:\n%s\n", before, after)
	})
	t.Run("Ensure ConfListWithNoSubnet is parsed and unparsed properly", func(t *testing.T) {
		before := getConfListWithNoSubnet()
		cl := new(ConfList)

		err := json.Unmarshal(before, cl)
		if err != nil {
			t.Fatalf("wasn't able to unmarshal JSON in test: %s", before)
		}

		after, err := json.MarshalIndent(cl, "", "  ")
		if err != nil {
			t.Fatalf("wasn't able to marshal JSON in test: %s", before)
		}

		assert.JSONEqf(t, string(before), string(after),
			"JSON is not equal!\nBefore:\n%s\nAfter:\n%s\n", before, after)
	})
	t.Run("Ensure ConfWithNoSubnet is parsed and unparsed properly", func(t *testing.T) {
		before := getConfWithNoSubnet()
		c := new(Conf)

		err := json.Unmarshal(before, c)
		if err != nil {
			t.Fatalf("wasn't able to unmarshal JSON in test: %s", before)
		}

		after, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			t.Fatalf("wasn't able to marshal JSON in test: %s", before)
		}

		assert.JSONEqf(t, string(before), string(after),
			"JSON is not equal!\nBefore:\n%s\nAfter:\n%s\n", before, after)
	})
}

func TestNewCNINetworkConfig(t *testing.T) {
	testcases := []struct {
		name       string
		filename   string
		isConfList bool
		content    []byte
		err        error
		ranges     []string
	}{
		{
			name:       "Attempt reading from conf",
			filename:   "10-kuberouter.conf",
			isConfList: false,
			content:    getConf(),
			err:        nil,
		},
		{
			name:       "Attempt reading from conflist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfList(),
			err:        nil,
		},
		{
			name:       "Ensure error upon reading from conf with no type",
			filename:   "10-kuberouter.conf",
			isConfList: false,
			content:    getConfWithNoType(),
			err:        fmt.Errorf("error load CNI config, file appears to have no type: "),
		},
		{
			name:       "Ensure error upon reading from conflist with no plugins",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithNoPlugins(),
			err:        fmt.Errorf("CNI config list "),
		},
		{
			name:       "Ensure conf subnet get consolidated into ranges when only subnet exists",
			filename:   "10-kuberouter.conf",
			isConfList: false,
			content:    getConf(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24"},
		},
		{
			name:       "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfList(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24"},
		},
		{
			name:       "Ensure conflist subnets get consolidated with ranges when both exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithRanges(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:       "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithDuplicateRanges(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, tmpDir, err := createFile(testcase.content, testcase.filename)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			cni, err := NewCNINetworkConfig(file.Name())
			if err != nil {
				if testcase.err == nil {
					assert.Fail(t, "if error from NewCNINetworkConfig is not nil, the testcase shouldn't be "+
						"nil either")
				}
				assert.True(t, strings.HasPrefix(err.Error(), testcase.err.Error()))
				return
			}

			assert.Equal(t, testcase.isConfList, cni.IsConfList())

			if testcase.ranges != nil {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Subnet,
					"subnet of cniNetworkConfig should always be empty because it should be consolidated with "+
						"ranges upon creation")

				foundSubnets := make(map[string]interface{}, 0)
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
		name       string
		filename   string
		isConfList bool
		content    []byte
		err        error
		ranges     []string
	}{
		{
			name:       "Ensure conf subnet get consolidated into ranges when only subnet exists",
			filename:   "10-kuberouter.conf",
			isConfList: false,
			content:    getConf(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24"},
		},
		{
			name:       "Ensure conflist subnet get consolidated into ranges when only subnet exists",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfList(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24"},
		},
		{
			name:       "Ensure conflist subnets get consolidated with ranges when both exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithRanges(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
		},
		{
			name:       "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithDuplicateRanges(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
		},
		{
			name:       "Ensure conflist subnets get de-deduplicated with ranges when repeats exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithIPv6DuplicateRanges(),
			err:        nil,
			ranges:     []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "2001:db8:42:2::/64"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, tmpDir, err := createFile(testcase.content, testcase.filename)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			cni, err := NewCNINetworkConfig(file.Name())
			assert.Equal(t, testcase.err, err)
			if err != nil {
				return
			}

			assert.Equal(t, testcase.isConfList, cni.IsConfList())

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
		filename     string
		isConfList   bool
		content      []byte
		err          error
		ranges       []string
		insertRanges []string
	}{
		{
			name:         "Ensure passed CIDR is properly inserted into a CNI conf with no subnets defined",
			filename:     "10-kuberouter.conf",
			isConfList:   false,
			content:      getConfWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure multiple CIDRs are properly inserted into a CNI conf with no subnets defined",
			filename:     "10-kuberouter.conflist",
			isConfList:   true,
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name: "Ensure multiple IPv4 & IPv6 CIDRs are properly inserted into a CNI conf with no subnets" +
				"defined",
			filename:     "10-kuberouter.conflist",
			isConfList:   true,
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:       "Ensure that new subnets are inserted into a conflist with existing ranges",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithRanges(),
			err:        nil,
			ranges: []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24",
				"10.242.5.0/24", "10.242.6.0/24"},
			insertRanges: []string{"10.242.5.0/24", "10.242.6.0/24"},
		},
		{
			name:         "Ensure duplicates are not inserted without error",
			filename:     "10-kuberouter.conflist",
			isConfList:   true,
			content:      getConfListWithDuplicateRanges(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24"},
			insertRanges: []string{"10.242.4.0/24"},
		},
		{
			name:       "Ensure error is thrown for bad cidr",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithDuplicateRanges(),
			err: fmt.Errorf("unable to parse input cidr: %s - %s", "10.242.4.0",
				"invalid CIDR address: 10.242.4.0"),
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24"},
			insertRanges: []string{"10.242.4.0"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, tmpDir, err := createFile(testcase.content, testcase.filename)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			cni, err := NewCNINetworkConfig(file.Name())
			if err != nil {
				assert.Fail(t, "err should always be nil when calling NewCNINetworkConfig for this suite")
			}

			for _, cidr := range testcase.insertRanges {
				err = cni.InsertPodCIDRIntoIPAM(cidr)
				assert.Equal(t, testcase.err, err)
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
		filename     string
		isConfList   bool
		content      []byte
		err          error
		ranges       []string
		insertRanges []string
	}{
		{
			name:       "Ensure written file is the same as read file when no ranges were inserted",
			filename:   "10-kuberouter.conf",
			isConfList: false,
			content:    getConfWithNoSubnet(),
			err:        nil,
		},
		{
			name:         "Ensure written conf file contains single subnet",
			filename:     "10-kuberouter.conf",
			isConfList:   false,
			content:      getConf(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24"},
			insertRanges: []string{"10.242.0.0/24"},
		},
		{
			name:         "Ensure written conflist file contains multiple subnets",
			filename:     "10-kuberouter.conflist",
			isConfList:   true,
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "10.242.1.0/24"},
			insertRanges: []string{"10.242.0.0/24", "10.242.1.0/24"},
		},
		{
			name:         "Ensure written conflist file has IPv4 & IPv6 CIDRs properly inserted",
			filename:     "10-kuberouter.conflist",
			isConfList:   true,
			content:      getConfListWithNoSubnet(),
			err:          nil,
			ranges:       []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
			insertRanges: []string{"10.242.0.0/24", "2001:db8:42:2::/64"},
		},
		{
			name:       "Ensure that conflist file has multiple subnets written when ranges already exist",
			filename:   "10-kuberouter.conflist",
			isConfList: true,
			content:    getConfListWithRanges(),
			err:        nil,
			ranges: []string{"10.242.0.0/24", "10.242.1.0/24", "10.242.2.0/24", "10.242.3.0/24", "10.242.4.0/24",
				"10.242.5.0/24", "10.242.6.0/24"},
			insertRanges: []string{"10.242.5.0/24", "10.242.6.0/24"},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, tmpDir, err := createFile(testcase.content, testcase.filename)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			cni, err := NewCNINetworkConfig(file.Name())
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
			cniFileBytes, err := os.ReadFile(file.Name())
			if err != nil {
				t.Fatalf("we should be able to read the CNI file we just wrote to")
			}
			var brPlug *Conf
			if cni.IsConfList() {
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

			cni, err = NewCNINetworkConfig(file.Name())
			if err != nil {
				assert.Fail(t, "err should always be nil when calling NewCNINetworkConfig for this suite")
			}

			if testcase.ranges != nil {
				assert.Emptyf(t, cni.getBridgePlugin().IPAM.Subnet,
					"subnet of cniNetworkConfig should always be empty because it should be consolidated with "+
						"ranges upon creation")

				foundSubnets := make(map[string]interface{}, 0)
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

func createFile(content []byte, filename string) (*os.File, string, error) {
	dir, err := os.MkdirTemp("", "kube-router-cni-test")
	if err != nil {
		return nil, "", fmt.Errorf("cannot create tmpdir: %v", err)
	}
	fullPath := path.Join(dir, filename)
	file, err := os.Create(fullPath)
	if err != nil {
		return nil, "", fmt.Errorf("cannot create file: %v", err)
	}

	if _, err = file.Write(content); err != nil {
		return nil, "", fmt.Errorf("cannot write to file: %v", err)
	}

	fmt.Println("File is ", file.Name())
	return file, dir, nil
}
