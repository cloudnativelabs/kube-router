package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
)

type cniNetworkConfig struct {
	FilePath string
	Conf     *Conf
	ConfList *ConfList
}

func NewCNINetworkConfig(cniConfFilePath string) (*cniNetworkConfig, error) {
	cniNetConf := cniNetworkConfig{
		FilePath: cniConfFilePath,
	}

	cniFileBytes, err := os.ReadFile(cniConfFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", cniConfFilePath, err)
	}

	// If we're working with a conflist setup
	if cniNetConf.IsConfList() {
		confList := new(ConfList)
		err = json.Unmarshal(cniFileBytes, confList)
		if err != nil {
			return nil, fmt.Errorf("failed to load CNI conflist file: %v", err)
		}
		if len(confList.Plugins) == 0 {
			return nil, fmt.Errorf("CNI config list %s has no plugins", cniConfFilePath)
		}
		cniNetConf.ConfList = confList
	} else {
		// If we're working with a conf setup
		conf := new(Conf)
		err = json.Unmarshal(cniFileBytes, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to load CNI conf file: %v", err)
		}
		if conf.Type == "" {
			return nil, fmt.Errorf("error load CNI config, file appears to have no type: %s", cniConfFilePath)
		}
		cniNetConf.Conf = conf
	}

	if err = cniNetConf.consolidateSubnets(); err != nil {
		return nil, err
	}

	return &cniNetConf, nil
}

// consolidateSubnets Many people still define the legacy single subnet variation of the IPAM plugin instead of the
// newer ranges variation. To account for this and make parsing simpler, we do the same thing that the official IPAM
// config loader does and collapse them into ranges.
func (c *cniNetworkConfig) consolidateSubnets() error {
	brPlug := c.getBridgePlugin()
	if brPlug.IPAM.Subnet != "" {
		err := c.InsertPodCIDRIntoIPAM(brPlug.IPAM.Subnet)
		if err != nil {
			return err
		}
		brPlug.IPAM.Subnet = ""
		delete(brPlug.IPAM.raw, "subnet")
	}

	return nil
}

// IsConfList checks to see if this CNI configuration is a *.conflist file or if it is a *.conf file. Returns true for
// *.conflist, returns false for anything else.
func (c *cniNetworkConfig) IsConfList() bool {
	return strings.HasSuffix(strings.ToLower(c.FilePath), ".conflist")
}

// getPodCIDRsMapFromCNISpec gets pod CIDR allocated to the node as a map from CNI spec file and returns it
func (c *cniNetworkConfig) getPodCIDRsMapFromCNISpec() (map[string]*net.IPNet, error) {
	podCIDRs := make(map[string]*net.IPNet)

	ipamConfig := c.getBridgePlugin().IPAM

	// Parse ranges from ipamConfig
	if ipamConfig != nil && len(ipamConfig.Ranges) > 0 {
		for _, rangeSet := range ipamConfig.Ranges {
			for _, item := range rangeSet {
				if item.Subnet != "" {
					_, netCIDR, err := net.ParseCIDR(item.Subnet)
					if err != nil {
						return nil, fmt.Errorf("unable to parse CIDR '%s' contained in CNI: %s",
							item.Subnet, c.FilePath)
					}
					podCIDRs[netCIDR.String()] = netCIDR
				}
			}
		}
	}

	return podCIDRs, nil
}

// GetPodCIDRsFromCNISpec gets pod CIDR allocated to the node from CNI spec file and returns it
func (c *cniNetworkConfig) GetPodCIDRsFromCNISpec() ([]*net.IPNet, error) {
	podCIDRMap, err := c.getPodCIDRsMapFromCNISpec()
	if err != nil {
		return nil, err
	}
	podCIDRs := make([]*net.IPNet, 0)
	for _, podCIDR := range podCIDRMap {
		podCIDRs = append(podCIDRs, podCIDR)
	}
	return podCIDRs, nil
}

// getBridgePlugin get the bridge plugin configuration out of the cniNetworkConfig in a consistent manner
func (c *cniNetworkConfig) getBridgePlugin() *Conf {
	if c.ConfList != nil {
		for _, conf := range c.ConfList.Plugins {
			if conf.Type == "bridge" {
				return conf
			}
		}
	}
	return c.Conf
}

// InsertPodCIDRIntoIPAM insert a new cidr into the CNI file. If the CIDR already exists in the CNI ranges, then
// operation is a noop. Throws an error if either the passed cidr cannot be parsed or if there is a problem with the
// CIDRs already in the CNI config.
func (c *cniNetworkConfig) InsertPodCIDRIntoIPAM(cidr string) error {
	ipamConfig := c.getBridgePlugin().IPAM

	// This should have already been sanitized by the GetPodCIDR* functions before it comes to us, but you can never be
	// too safe...
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("unable to parse input cidr: %s - %v", cidr, err)
	}

	// Check that we don't already have the cidr in our list of ranges already, if so, consider it a no-op
	existingPodCIDRs, err := c.getPodCIDRsMapFromCNISpec()
	if err != nil {
		return err
	}
	if _, ok := existingPodCIDRs[cidr]; ok {
		return nil
	}

	// Add the CIDR that was passed to us
	newRange := []*Range{{raw: make(map[string]json.RawMessage), Subnet: cidr}}
	ipamConfig.Ranges = append(ipamConfig.Ranges, newRange)

	return nil
}

func (c *cniNetworkConfig) SetMTU(mtu int) {
	brPlugin := c.getBridgePlugin()
	brPlugin.MTU = float64(mtu)
}

func (c *cniNetworkConfig) WriteCNIConfig() error {
	var cniBytes []byte
	var err error
	if c.IsConfList() {
		cniBytes, err = json.Marshal(c.ConfList)
		if err != nil {
			return fmt.Errorf("unable to marshal CNI ConfList: %v", err)
		}
	} else {
		cniBytes, err = json.Marshal(c.Conf)
		if err != nil {
			return fmt.Errorf("unable to marshal CNI Conf: %v", err)
		}
	}

	err = os.WriteFile(c.FilePath, cniBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write into CNI conf file: %v", err)
	}

	return nil
}

// This elaborate re-definition of the stuff inside libcni is necessary because the upstream cni structs and funcs were
// only ever meant to unmarshal data. Since each struct only defines the needs of the specific plugins (like bridge or
// ipam), they often times leave out the fields belonging to other plugins. This means when we go to marshal the data
// back into JSON we'll drop fields that are important to other plugins.
//
// So instead, we create a special set of utility structs and funcs that are capable of partially unmarshal-ing JSON
// data. Parsing the information we care about, and leaving the data that we don't care about and may not even know
// about alone. Then it is able to faithfully re-marshal the resulting structs back into their JSON form without losing
// data.
//
// This is very similar to the way that the PerimeterX/marshmallow (https://github.com/PerimeterX/marshmallow) library
// works, except that these functions are capable of marshaling the JSON back to its original form reliably. Whereas
// marshmallow is only able to unmarshal the data[

// rawMapAble interface that denotes an object for which we are able to convert it to a list of keys associated with
// raw JSON byte data
type rawMapAble interface {
	getRaw() *map[string]json.RawMessage
}

// All of our CNI based structs are listed here. Each struct only has the fields that we use to specifically read or
// write data to / from.

// ConfList represents a list of CNI configurations
type ConfList struct {
	Plugins []*Conf
	raw     map[string]json.RawMessage
}

// Conf represents the individual CNI configuration that may exist on its own, or be part of a ConfList
type Conf struct {
	Bridge string
	IPAM   *IPAM
	MTU    float64
	Type   string
	raw    map[string]json.RawMessage
}

// IPAM represents the ipam specific configuration that may exist on a given CNI configuration / plugin
type IPAM struct {
	Subnet string
	Ranges [][]*Range
	raw    map[string]json.RawMessage
}

// Range represents an IP range that may exist within a range set (hence the double array above)
type Range struct {
	Subnet string
	raw    map[string]json.RawMessage
}

// The following are the implementations of rawMapAble, json.Marshaler, & json.Unmarshaler for each of the above
// structs. Each struct requires the following methods in order to be marshaled / unmarshaled:
// * getRaw() *map[string]json.RawMessage
// * UnmarshalJSON(bytes []byte) error
// * MarshalJson() ([]bytes, error)

func (c *ConfList) getRaw() *map[string]json.RawMessage {
	return &c.raw
}

func (c *ConfList) UnmarshalJSON(bytes []byte) error {
	return PartialJSONUnmarshal(c, bytes)
}

func (c *ConfList) MarshalJSON() ([]byte, error) {
	return PartialJSONMarshal(c)
}

func (c *Conf) getRaw() *map[string]json.RawMessage {
	return &c.raw
}

func (c *Conf) UnmarshalJSON(bytes []byte) error {
	return PartialJSONUnmarshal(c, bytes)
}

func (c *Conf) MarshalJSON() ([]byte, error) {
	return PartialJSONMarshal(c)
}

func (i *IPAM) getRaw() *map[string]json.RawMessage {
	return &i.raw
}

func (i *IPAM) UnmarshalJSON(bytes []byte) error {
	return PartialJSONUnmarshal(i, bytes)
}

func (i *IPAM) MarshalJSON() ([]byte, error) {
	return PartialJSONMarshal(i)
}

func (r *Range) getRaw() *map[string]json.RawMessage {
	return &r.raw
}

func (r *Range) UnmarshalJSON(bytes []byte) error {
	return PartialJSONUnmarshal(r, bytes)
}

func (r *Range) MarshalJSON() ([]byte, error) {
	return PartialJSONMarshal(r)
}

// PartialJSONUnmarshal allows a struct that implements the rawMapAble interface to be partially unmarshaled. This means
// that via this function we are able to parse and understand the fields that we know about and have defined in the
// struct without knowing every possible field. This still stores the unknown fields and they can be retrieved via the
// getRaw() function and restored properly via the PartialJSONMarshal() function.
func PartialJSONUnmarshal(r rawMapAble, bytes []byte) error {
	// Unmarshal the full element into map[string]json.RawMessage so that we can ensure that we capture all elements
	// and not just the ones that we have struct fields for
	raw := r.getRaw()
	if err := json.Unmarshal(bytes, raw); err != nil {
		return err
	}

	// Go through the struct that lies under the rawMapAble interface and loop through all of its fields
	val := reflect.ValueOf(r).Elem()
	for i := 0; i < val.NumField(); i++ {
		// Get the name and value of the field for later use
		name := strings.ToLower(val.Type().Field(i).Name)
		valueField := val.Field(i)
		if name == "raw" {
			continue
		}

		// If a name from the underlying struct exists in the raw message, then send it for more complete unmarshalling
		if valFromRaw, ok := (*raw)[name]; ok {
			if !valueField.CanAddr() {
				// Make sure that the value is capable of addressing before we try it below and get a panic
				continue
			}

			// Unmarshal the raw JSON into the specific interface of the underlying struct, this second pass at
			// unmarshalling is how we populate specific fields in our struct rather than just working with raw JSON
			if err := json.Unmarshal(valFromRaw, valueField.Addr().Interface()); err != nil {
				return err
			}
		}
	}

	return nil
}

// isNilOrEmpty Unfortunately, we cannot blindly call the IsNil() function on reflect.Value as there are many types like
// strings that are not able to have a nil value and it will cause a panic
func isNilOrEmpty(v reflect.Value) bool {
	//nolint:exhaustive // we don't care about all of the potential types here, only the ones that might trip us up
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return v.IsNil()
	case reflect.String:
		return v.Interface() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return v.IsZero()
	}
	return false
}

// PartialJSONMarshal allows a struct that implements the rawMapAble interface to be fully restored without having
// to know about every possible field that may exist within the JSON. This is the reverse process of
// PartialJSONUnmarshal().
func PartialJSONMarshal(r rawMapAble) ([]byte, error) {
	raw := r.getRaw()

	// Find the value of our RawAble struct passed in
	val := reflect.ValueOf(r).Elem()
	// Iterate over all the fields in the passed struct
	for i := 0; i < val.NumField(); i++ {
		name := strings.ToLower(val.Type().Field(i).Name)
		valueField := val.Field(i)
		if name == "raw" {
			// Don't attempt to marshal our raw field as that's where we are marshaling to
			continue
		}
		if !valueField.CanAddr() {
			// Make sure that the value is capable of addressing before we try it below and get a panic
			continue
		}
		if isNilOrEmpty(valueField) {
			// Don't load up the marshaled JSON with a bunch of null values
			continue
		}

		// We are now reasonably certain that we have a field on the passed struct that is:
		// * not our raw field
		// * can be addressed
		// * is not nil
		// Let's marshal it!
		bytes, err := json.Marshal(valueField.Addr().Interface())
		if err != nil {
			return nil, err
		}

		// Take the marshaled value and store it in the raw map alongside other keys that we don't care about and were
		// never unmarshalled
		(*raw)[name] = bytes
	}

	// Finally marshal our raw map which contains both parsed and unparsed fields
	return json.Marshal(raw)
}
