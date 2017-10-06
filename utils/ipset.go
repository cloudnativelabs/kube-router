package utils

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var (
	// Error returned when ipset binary is not found.
	errIpsetNotFound = errors.New("Ipset utility not found")
)

const (
	// FamillyInet IPV4.
	FamillyInet = "inet"
	// FamillyInet6 IPV6.
	FamillyInet6 = "inet6"

	// DefaultMaxElem Default OptionMaxElem value.
	DefaultMaxElem = "65536"
	// DefaultHasSize Defaul OptionHashSize value.
	DefaultHasSize = "1024"

	// TypeHashIP The hash:ip set type uses a hash to store IP host addresses (default) or network addresses. Zero valued IP address cannot be stored in a hash:ip type of set.
	TypeHashIP = "hash:ip"
	// TypeHashMac The hash:mac set type uses a hash to store MAC addresses. Zero valued MAC addresses cannot be stored in a hash:mac type of set.
	TypeHashMac = "hash:mac"
	// TypeHashNet The hash:net set type uses a hash to store different sized IP network addresses. Network address with zero prefix size cannot be stored in this type of sets.
	TypeHashNet = "hash:net"
	// TypeHashNetNet The hash:net,net set type uses a hash to store pairs of different sized IP network addresses. Bear in mind that the first parameter has precedence over the second, so a nomatch entry could be potentially be ineffective if a more specific first parameter existed with a suitable second parameter. Network address with zero prefix size cannot be stored in this type of set.
	TypeHashNetNet = "hash:net,net"
	// TypeHashIPPort The hash:ip,port set type uses a hash to store IP address and port number pairs. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.
	TypeHashIPPort = "hash:ip,port"
	// TypeHashNetPort The hash:net,port set type uses a hash to store different sized IP network address and port pairs. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used. Network address with zero prefix size is not accepted either.
	TypeHashNetPort = "hash:net,port"
	// TypeHashIPPortIP The hash:ip,port,ip set type uses a hash to store IP address, port number and a second IP address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.
	TypeHashIPPortIP = "hash:ip,port,ip"
	// TypeHashIPPortNet The hash:ip,port,net set type uses a hash to store IP address, port number and IP network address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used. Network address with zero prefix size cannot be stored either.
	TypeHashIPPortNet = "hash:ip,port,net"
	// TypeHashIPMark The hash:ip,mark set type uses a hash to store IP address and packet mark pairs.
	TypeHashIPMark = "hash:ip,mark"
	// TypeHashIPNetPortNet The hash:net,port,net set type behaves similarly to hash:ip,port,net but accepts a cidr value for both the first and last parameter. Either subnet is permitted to be a /0 should you wish to match port between all destinations.
	TypeHashIPNetPortNet = "hash:net,port,net"
	// TypeHashNetIface The hash:net,iface set type uses a hash to store different sized IP network address and interface name pairs.
	TypeHashNetIface = "hash:net,iface"
	// TypeListSet The list:set type uses a simple list in which you can store set names.
	TypeListSet = "list:set"

	// OptionTimeout All set types supports the optional timeout parameter when creating a set and adding entries. The value of the timeout parameter for the create command means the default timeout value (in seconds) for new entries. If a set is created with timeout support, then the same timeout option can be used to specify non-default timeout values when adding entries. Zero timeout value means the entry is added permanent to the set. The timeout value of already added elements can be changed by readding the element using the -exist option. When listing the set, the number of entries printed in the header might be larger than the listed number of entries for sets with the timeout extensions: the number of entries in the set is updated when elements added/deleted to the set and periodically when the garbage colletor evicts the timed out entries.`
	OptionTimeout = "timeout"
	// OptionCounters All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionCounters = "counters"
	// OptionPackets All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionPackets = "packets"
	// OptionBytes All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionBytes = "bytes"
	// OptionComment All set types support the optional comment extension. Enabling this extension on an ipset enables you to annotate an ipset entry with an arbitrary string. This string is completely ignored by both the kernel and ipset itself and is purely for providing a convenient means to document the reason for an entry's existence. Comments must not contain any quotation marks and the usual escape character (\) has no meaning
	OptionComment = "comment"
	// OptionSkbinfo All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbinfo = "skbinfo"
	// OptionSkbmark All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbmark = "skbmark"
	// OptionSkbprio All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbprio = "skbprio"
	// OptionSkbqueue All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbqueue = "skbqueue"
	// OptionHashSize This parameter is valid for the create command of all hash type sets. It defines the initial hash size for the set, default is 1024. The hash size must be a power of two, the kernel automatically rounds up non power of two hash sizes to the first correct value.
	OptionHashSize = "hashsize"
	// OptionMaxElem This parameter is valid for the create command of all hash type sets. It does define the maximal number of elements which can be stored in the set, default 65536.
	OptionMaxElem = "maxelem"
	// OptionFamilly This parameter is valid for the create command of all hash type sets except for hash:mac. It defines the protocol family of the IP addresses to be stored in the set. The default is inet, i.e IPv4.
	OptionFamilly = "family"
	// OptionNoMatch The hash set types which can store net type of data (i.e. hash:*net*) support the optional nomatch option when adding entries. When matching elements in the set, entries marked as nomatch are skipped as if those were not added to the set, which makes possible to build up sets with exceptions. See the example at hash type hash:net below. When elements are tested by ipset, the nomatch flags are taken into account. If one wants to test the existence of an element marked with nomatch in a set, then the flag must be specified too.
	OptionNoMatch = "nomatch"
	// OptionForceAdd All hash set types support the optional forceadd parameter when creating a set. When sets created with this option become full the next addition to the set may succeed and evict a random entry from the set.
	OptionForceAdd = "forceadd"
)

// IPSet represent ipset sets managed by.
type IPSet struct {
	// ipset bianry path.
	ipSetPath *string
	// Sets maintainted by ipset.
	Sets map[string]*Set
}

// Set reprensent a ipset set entry.
type Set struct {
	// ipset parent to get ipSetPath.
	IPSet *IPSet
	// set name.
	Name string
	// set entries.
	Entries []*Entry
	// set created options.
	Options []string
}

// Entry of ipset Set.
type Entry struct {
	// set parent to get ipSetPath.
	Set *Set
	// entry created options.
	Options []string
}

// Get ipset binary path or return an error.
func getIPSetPath() (*string, error) {
	path, err := exec.LookPath("ipset")
	if err != nil {
		return nil, errIpsetNotFound
	}
	return &path, nil
}

// Used to run ipset binary with args and return stdout.
func (set *IPSet) run(args ...string) (string, error) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd := exec.Cmd{
		Path:   *set.ipSetPath,
		Args:   append([]string{*set.ipSetPath}, args...),
		Stderr: &stderr,
		Stdout: &stdout,
	}

	if err := cmd.Run(); err != nil {
		return "", errors.New(stderr.String())
	}

	return stdout.String(), nil
}

// Used to run ipset binary with arg and inject stdin buffer and return stdout.
func (set *IPSet) runWithStdin(stdin *bytes.Buffer, args ...string) (string, error) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd := exec.Cmd{
		Path:   *set.ipSetPath,
		Args:   append([]string{*set.ipSetPath}, args...),
		Stderr: &stderr,
		Stdout: &stdout,
		Stdin:  stdin,
	}

	if err := cmd.Run(); err != nil {
		return "", errors.New(stderr.String())
	}

	return stdout.String(), nil
}

// NewIPSet create a new IPSet with ipSetPath initialized.
func NewIPSet() (*IPSet, error) {
	ipSetPath, err := getIPSetPath()
	if err != nil {
		return nil, err
	}
	ipSet := &IPSet{
		ipSetPath: ipSetPath,
		Sets:      make(map[string]*Set),
	}
	return ipSet, nil
}

// Create a set identified with setname and specified type. The type may require type specific options. If the -exist option is specified, ipset ignores the error otherwise raised when the same set (setname and create parameters are identical) already exists.
func (ipSet *IPSet) Create(setName string, createOptions ...string) (*Set, error) {
	set := &Set{
		Name:    setName,
		Options: createOptions,
		IPSet:   ipSet,
	}
	ipSet.Sets[setName] = set
	_, err := ipSet.run(append([]string{"create", "-exist", set.Name}, createOptions...)...)
	if err != nil {
		return nil, err
	}
	return set, nil
}

// Add a given entry to the set. If the -exist option is specified, ipset ignores if the entry already added to the set.
func (set *Set) Add(addOptions ...string) (*Entry, error) {
	entry := &Entry{
		Set:     set,
		Options: addOptions,
	}
	set.Entries = append(set.Entries, entry)
	_, err := set.IPSet.run(append([]string{"add", "-exist", entry.Set.Name}, addOptions...)...)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// Del an entry from a set. If the -exist option is specified and the entry is not in the set (maybe already expired), then the command is ignored.
func (entry *Entry) Del() error {
	_, err := entry.Set.IPSet.run(append([]string{"del", entry.Set.Name}, entry.Options...)...)
	if err != nil {
		return err
	}
	entry.Set.IPSet.Save()
	return nil
}

// Test wether an entry is in a set or not. Exit status number is zero if the tested entry is in the set and nonzero if it is missing from the set.
func (set *Set) Test(testOptions ...string) (bool, error) {
	_, err := set.IPSet.run(append([]string{"test", set.Name}, testOptions...)...)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Destroy the specified set or all the sets if none is given. If the set has got reference(s), nothing is done and no set destroyed.
func (set *Set) Destroy() error {
	_, err := set.IPSet.run("destroy", set.Name)
	if err != nil {
		return err
	}
	return nil
}

// Destroy the specified set or all the sets if none is given. If the set has got reference(s), nothing is done and no set destroyed.
func (set *IPSet) Destroy() error {
	_, err := set.run("destroy")
	if err != nil {
		return err
	}
	return nil
}

// Parse ipset save stdout.
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func parseIPSetSave(ipSet *IPSet, result string) map[string]*Set {
	sets := make(map[string]*Set)
	// Save is always in order
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		content := strings.Split(line, " ")
		if content[0] == "create" {
			sets[content[1]] = &Set{
				IPSet:   ipSet,
				Name:    content[1],
				Options: content[2:],
			}
		} else if content[0] == "add" {
			set := sets[content[1]]
			set.Entries = append(set.Entries, &Entry{
				Set:     set,
				Options: content[2:],
			})
		}
	}

	return sets
}

// Build ipset restore input
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func buildIPSetRestore(ipSet *IPSet) string {
	ipSetRestore := ""
	for _, set := range ipSet.Sets {
		ipSetRestore += fmt.Sprintf("create %s %s\n", set.Name, strings.Join(set.Options[:], " "))
		for _, entry := range set.Entries {
			ipSetRestore += fmt.Sprintf("add %s %s\n", set.Name, strings.Join(entry.Options[:], " "))
		}
	}
	return ipSetRestore
}

// Save the given set, or all sets if none is given to stdout in a format that restore can read. The option -file can be used to specify a filename instead of stdout.
// save "ipset save" command output to ipset.sets.
func (set *IPSet) Save() error {
	stdout, err := set.run("save")
	if err != nil {
		return err
	}
	set.Sets = parseIPSetSave(set, stdout)
	return nil
}

// Restore a saved session generated by save. The saved session can be fed from stdin or the option -file can be used to specify a filename instead of stdin. Please note, existing sets and elements are not erased by restore unless specified so in the restore file. All commands are allowed in restore mode except list, help, version, interactive mode and restore itself.
// Send formated ipset.sets into stdin of "ipset restore" command.
func (set *IPSet) Restore() error {
	stdin := bytes.NewBufferString(buildIPSetRestore(set))
	_, err := set.runWithStdin(stdin, "restore", "-exist")
	if err != nil {
		return err
	}
	return nil
}

// Flush all entries from the specified set or flush all sets if none is given.
func (set *Set) Flush() error {
	_, err := set.IPSet.run("flush", set.Name)
	if err != nil {
		return err
	}
	return nil
}

// Flush all entries from the specified set or flush all sets if none is given.
func (set *IPSet) Flush() error {
	_, err := set.run("flush")
	if err != nil {
		return err
	}
	return nil
}

// Get Set by Name.
func (ipset *IPSet) Get(setName string) *Set {
	return ipset.Sets[setName]
}

// Rename a set. Set identified by SETNAME-TO must not exist.
func (set *Set) Rename(newName string) error {
	_, err := set.IPSet.run("rename", set.Name, newName)
	if err != nil {
		return err
	}
	return nil
}

// Swap the content of two sets, or in another words, exchange the name of two sets. The referred sets must exist and compatible type of sets can be swapped only.
func (set *Set) Swap(setTo *Set) error {
	_, err := set.IPSet.run("rename", set.Name, setTo.Name)
	if err != nil {
		return err
	}
	return nil
}

// Refresh a Set with new entries.
func (set *Set) Refresh(entries []string, extraOptions ...string) error {
	tempName := set.Name + "-temp"
	s := &Set{
		IPSet:   set.IPSet,
		Name:    tempName,
		Options: set.Options,
	}

	for _, entry := range entries {
		s.Entries = append(s.Entries, &Entry{
			Set:     s,
			Options: append([]string{entry}, extraOptions...),
		})
	}
	set.IPSet.Sets[tempName] = s
	err := set.IPSet.Restore()
	if err != nil {
		return err
	}

	err = set.Swap(s)
	if err != nil {
		return err
	}

	err = s.Destroy()
	if err != nil {
		return err
	}

	s.Name = set.Name
	set.IPSet.Sets[set.Name] = s
	delete(set.IPSet.Sets, tempName)

	return nil
}
