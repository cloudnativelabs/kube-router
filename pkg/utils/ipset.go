package utils

import (
	"bytes"
	//nolint:gosec // we don't use this hash in a sensitive capacity, so we don't care that its weak
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"k8s.io/klog/v2"
)

var (
	// Error returned when ipset binary is not found.
	errIpsetNotFound = errors.New("ipset utility not found")
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

	// TypeHashIP The hash:ip set type uses a hash to store IP host addresses (default) or network addresses. Zero
	// valued IP address cannot be stored in a hash:ip type of set.
	TypeHashIP = "hash:ip"
	// TypeHashMac The hash:mac set type uses a hash to store MAC addresses. Zero valued MAC addresses cannot be stored
	// in a hash:mac type of set.
	TypeHashMac = "hash:mac"
	// TypeHashNet The hash:net set type uses a hash to store different sized IP network addresses. Network address with
	// zero prefix size cannot be stored in this type of sets.
	TypeHashNet = "hash:net"
	// TypeHashNetNet The hash:net,net set type uses a hash to store pairs of different sized IP network addresses. Bear
	// in mind that the first parameter has precedence over the second, so a nomatch entry could be potentially be
	// ineffective if a more specific first parameter existed with a suitable second parameter. Network address with
	// zero prefix size cannot be stored in this type of set.
	TypeHashNetNet = "hash:net,net"
	// TypeHashIPPort The hash:ip,port set type uses a hash to store IP address and port number pairs. The port number
	// is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.
	TypeHashIPPort = "hash:ip,port"
	// TypeHashNetPort The hash:net,port set type uses a hash to store different sized IP network address and port
	// pairs. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be
	// used. Network address with zero prefix size is not accepted either.
	TypeHashNetPort = "hash:net,port"
	// TypeHashIPPortIP The hash:ip,port,ip set type uses a hash to store IP address, port number and a second IP
	// address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number
	// cannot be used.
	TypeHashIPPortIP = "hash:ip,port,ip"
	// TypeHashIPPortNet The hash:ip,port,net set type uses a hash to store IP address, port number and IP network
	// address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number
	// cannot be used. Network address with zero prefix size cannot be stored either.
	TypeHashIPPortNet = "hash:ip,port,net"
	// TypeHashIPMark The hash:ip,mark set type uses a hash to store IP address and packet mark pairs.
	TypeHashIPMark = "hash:ip,mark"
	// TypeHashIPNetPortNet The hash:net,port,net set type behaves similarly to hash:ip,port,net but accepts a cidr
	// value for both the first and last parameter. Either subnet is permitted to be a /0 should you wish to match port
	// between all destinations.
	TypeHashIPNetPortNet = "hash:net,port,net"
	// TypeHashNetIface The hash:net,iface set type uses a hash to store different sized IP network address and
	// interface name pairs.
	TypeHashNetIface = "hash:net,iface"
	// TypeListSet The list:set type uses a simple list in which you can store set names.
	TypeListSet = "list:set"

	// OptionTimeout All set types supports the optional timeout parameter when creating a set and adding entries. The
	// value of the timeout parameter for the create command means the default timeout value (in seconds) for new
	// entries. If a set is created with timeout support, then the same timeout option can be used to specify
	// non-default timeout values when adding entries. Zero timeout value means the entry is added permanent to the
	// set. The timeout value of already added elements can be changed by readding the element using the -exist option.
	// When listing the set, the number of entries printed in the header might be larger than the listed number of
	// entries for sets with the timeout extensions: the number of entries in the set is updated when elements
	// added/deleted to the set and periodically when the garbage colletor evicts the timed out entries.
	OptionTimeout = "timeout"
	// OptionCounters All set types support the optional counters option when creating a set. If the option is specified
	// then the set is created with packet and byte counters per element support. The packet and byte counters are
	// initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are
	// explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero
	// counter values.
	OptionCounters = "counters"
	// OptionPackets All set types support the optional counters option when creating a set. If the option is specified
	// then the set is created with packet and byte counters per element support. The packet and byte counters are
	// initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are
	// explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero
	// counter values.
	OptionPackets = "packets"
	// OptionBytes All set types support the optional counters option when creating a set. If the option is specified
	// then the set is created with packet and byte counters per element support. The packet and byte counters are
	// initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are
	// explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero
	// counter values.
	OptionBytes = "bytes"
	// OptionComment All set types support the optional comment extension. Enabling this extension on an ipset enables
	// you to annotate an ipset entry with an arbitrary string. This string is completely ignored by both the kernel and
	// ipset itself and is purely for providing a convenient means to document the reason for an entry's existence.
	// Comments must not contain any quotation marks and the usual escape character (\) has no meaning.
	OptionComment = "comment"
	// OptionSkbinfo All set types support the optional skbinfo extension. This extension allow to store the metainfo
	// (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter
	// target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers
	// with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format:
	// MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbinfo = "skbinfo"
	// OptionSkbmark All set types support the optional skbinfo extension. This extension allow to store the metainfo
	// (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter
	// target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers
	// with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format:
	//MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbmark = "skbmark"
	// OptionSkbprio All set types support the optional skbinfo extension. This extension allow to store the metainfo
	// (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter
	// target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers
	// with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format:
	// MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbprio = "skbprio"
	// OptionSkbqueue All set types support the optional skbinfo extension. This extension allow to store the metainfo
	// (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter
	// target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers
	// with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format:
	// MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbqueue = "skbqueue"
	// OptionHashSize This parameter is valid for the create command of all hash type sets. It defines the initial hash
	// size for the set, default is 1024. The hash size must be a power of two, the kernel automatically rounds up non
	// power of two hash sizes to the first correct value.
	OptionHashSize = "hashsize"
	// OptionMaxElem This parameter is valid for the create command of all hash type sets. It does define the maximal
	// number of elements which can be stored in the set, default 65536.
	OptionMaxElem = "maxelem"
	// OptionFamilly This parameter is valid for the create command of all hash type sets except for hash:mac. It
	// defines the protocol family of the IP addresses to be stored in the set. The default is inet, i.e IPv4.
	OptionFamilly = "family"
	// OptionNoMatch The hash set types which can store net type of data (i.e. hash:*net*) support the optional nomatch
	// option when adding entries. When matching elements in the set, entries marked as nomatch are skipped as if those
	// were not added to the set, which makes possible to build up sets with exceptions. See the example at hash type
	// hash:net below. When elements are tested by ipset, the nomatch flags are taken into account. If one wants to test
	// the existence of an element marked with nomatch in a set, then the flag must be specified too.
	OptionNoMatch = "nomatch"
	// OptionForceAdd All hash set types support the optional forceadd parameter when creating a set. When sets created
	// with this option become full the next addition to the set may succeed and evict a random entry from the set.
	OptionForceAdd = "forceadd"

	// tmpIPSetPrefix Is the prefix added to temporary ipset names used in the atomic swap operations during ipset
	// restore. You should never see these on your system because they only exist during the restore.
	tmpIPSetPrefix = "TMP-"

	// IPv6SetPrefix is the prefix that ipset requires on IPv6 ipsets in order to distinguish them from IPv4 sets
	IPv6SetPrefix = "inet6"
)

type IPSetHandler interface {
	Create(setName string, createOptions ...string) (*Set, error)
	Add(set *Set) error
	RefreshSet(setName string, entriesWithOptions [][]string, setType string)
	Destroy(setName string) error
	DestroyAllWithin() error
	Save() error
	Restore() error
	Flush() error
	Get(setName string) *Set
	Sets() map[string]*Set
	Name(ipSet string) string
}

// IPSet represent ipset sets managed by.
type IPSet struct {
	ipSetPath *string
	sets      map[string]*Set
	isIpv6    bool
}

// Set represent a ipset set entry.
type Set struct {
	Parent  *IPSet
	Name    string
	Entries []*Entry
	Options []string
}

// Entry of ipset Set.
type Entry struct {
	Set     *Set
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
func (ipset *IPSet) run(args ...string) (string, error) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	klog.V(9).Infof("running ipset command: path=`%s` args=%+v", *ipset.ipSetPath, args)
	cmd := exec.Cmd{
		Path:   *ipset.ipSetPath,
		Args:   append([]string{*ipset.ipSetPath}, args...),
		Stderr: &stderr,
		Stdout: &stdout,
	}

	if err := cmd.Run(); err != nil {
		return "", errors.New(stderr.String())
	}

	return stdout.String(), nil
}

// Used to run ipset binary with arg and inject stdin buffer and return stdout.
func (ipset *IPSet) runWithStdin(stdin *bytes.Buffer, args ...string) error {
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	klog.V(9).Infof("running ipset command: path=`%s` args=%+v stdin ```%s```",
		*ipset.ipSetPath, args, stdin.String())
	cmd := exec.Cmd{
		Path:   *ipset.ipSetPath,
		Args:   append([]string{*ipset.ipSetPath}, args...),
		Stderr: &stderr,
		Stdout: &stdout,
		Stdin:  stdin,
	}

	if err := cmd.Run(); err != nil {
		return errors.New(stderr.String())
	}

	return nil
}

// NewIPSet create a new IPSet with ipSetPath initialized.
func NewIPSet(isIpv6 bool) (*IPSet, error) {
	ipSetPath, err := getIPSetPath()
	if err != nil {
		return nil, err
	}
	ipSet := &IPSet{
		ipSetPath: ipSetPath,
		sets:      make(map[string]*Set),
		isIpv6:    isIpv6,
	}
	return ipSet, nil
}

// Create a set identified with setname and specified type. The type may
// require type specific options. Does not create set on the system if it
// already exists by the same name.
func (ipset *IPSet) Create(setName string, createOptions ...string) (*Set, error) {
	ipsetName := ipset.Name(setName)
	// Populate Set map if needed
	if ipset.Get(ipsetName) == nil {
		// check that caller didn't leave out ipv6 options, fill it in for them if they did
		ipv6OptionFound := false
		if ipset.isIpv6 {
			for idx, option := range createOptions {
				if option == "family" {
					if createOptions[idx+1] != "inet6" {
						return nil, fmt.Errorf("family option passed with a parameter that was not inet6 to an IPv6 "+
							"only ipset handler, detected family type passed: %s", createOptions[idx+1])
					}
					ipv6OptionFound = true
					break
				}
			}
			if !ipv6OptionFound {
				createOptions = append(createOptions, "family", "inet6")
			}
		}
		ipset.sets[ipsetName] = &Set{
			Name:    ipsetName,
			Options: createOptions,
			Parent:  ipset,
		}
	}

	// Determine if set with the same name is already active on the system
	setIsActive, err := ipset.sets[ipsetName].IsActive()
	if err != nil {
		return nil, fmt.Errorf("failed to determine if ipset set %s exists: %s",
			setName, err)
	}

	// Create set if missing from the system
	if !setIsActive {
		args := []string{"create", "-exist", ipset.sets[ipsetName].name()}
		args = append(args, createOptions...)
		klog.V(2).Infof("running ipset command: %s", args)
		_, err := ipset.run(args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create ipset set on system: %s", err)
		}
	}
	return ipset.sets[ipsetName], nil
}

// Add a given Set to an IPSet
func (ipset *IPSet) Add(set *Set) error {
	_, err := ipset.Create(set.name(), set.Options...)
	if err != nil {
		return err
	}

	options := make([][]string, len(set.Entries))
	for index, entry := range set.Entries {
		options[index] = entry.Options
	}

	err = ipset.Get(set.name()).BatchAdd(options)
	if err != nil {
		return err
	}

	return nil
}

// RefreshSet add/update internal Sets with a Set of entries but does not run restore command
func (ipset *IPSet) RefreshSet(setName string, entriesWithOptions [][]string, setType string) {
	ipsetName := ipset.Name(setName)
	if ipset.Get(ipsetName) == nil {
		options := []string{setType, OptionTimeout, "0"}
		if ipset.isIpv6 {
			options = append(options, "family", "inet6")
		}
		ipset.sets[ipsetName] = &Set{
			Name:    ipsetName,
			Options: options,
			Parent:  ipset,
		}
	}
	entries := make([]*Entry, len(entriesWithOptions))
	for i, entry := range entriesWithOptions {
		entries[i] = &Entry{Set: ipset.sets[ipsetName], Options: entry}
	}
	ipset.Get(ipsetName).Entries = entries
}

// BatchAdd given entries (with their options) to the set.
// For multiple items, this is much faster than Add().
func (set *Set) BatchAdd(addOptions [][]string) error {
	newEntries := make([]*Entry, len(addOptions))
	for index, options := range addOptions {
		entry := &Entry{
			Set:     set,
			Options: options,
		}
		newEntries[index] = entry
	}
	set.Entries = append(set.Entries, newEntries...)

	// Build the `restore` command contents
	var builder strings.Builder
	for _, options := range addOptions {
		line := strings.Join(append([]string{"add", "-exist", set.name()}, options...), " ")
		builder.WriteString(line + "\n")
	}
	restoreContents := builder.String()

	// Invoke the command
	err := set.Parent.runWithStdin(bytes.NewBufferString(restoreContents), "restore")
	if err != nil {
		return err
	}
	return nil
}

// Destroy the specified set or all the sets if none is given. If the set has
// got reference(s), nothing is done and no set destroyed.
func (set *Set) Destroy() error {
	_, err := set.Parent.run("destroy", set.name())
	if err != nil {
		return err
	}

	delete(set.Parent.sets, set.Name)
	return nil
}

// Destroy the specified set by name. If the set has got reference(s), nothing
// is done and no set destroyed. If the IPSet does not contain the named set
// then Destroy is a no-op.
func (ipset *IPSet) Destroy(setName string) error {
	set := ipset.Get(ipset.Name(setName))
	if set == nil {
		return nil
	}

	err := set.Destroy()
	if err != nil {
		return err
	}

	return nil
}

// DestroyAllWithin destroys all sets contained within the IPSet's Sets.
func (ipset *IPSet) DestroyAllWithin() error {
	for _, v := range ipset.sets {
		err := v.Destroy()
		if err != nil {
			return err
		}
	}

	return nil
}

// IsActive checks if a set exists on the system with the same name.
func (set *Set) IsActive() (bool, error) {
	_, err := set.Parent.run("list", set.name())
	if err != nil {
		if strings.Contains(err.Error(), "name does not exist") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// IPSetName returns the proper set name for this component based upon whether or not it is an IPv6 set
func IPSetName(setName string, isIPv6 bool) string {
	if isIPv6 && !strings.HasPrefix(setName, IPv6SetPrefix+":") {
		return fmt.Sprintf("%s:%s", IPv6SetPrefix, setName)
	}
	return setName
}

func (ipset *IPSet) Name(setName string) string {
	return IPSetName(setName, ipset.isIpv6)
}

func (set *Set) HasPrefix(prefix string) bool {
	fullPrefix := IPSetName(prefix, set.Parent.isIpv6)
	return strings.HasPrefix(set.name(), fullPrefix)
}

func (set *Set) name() string {
	return set.Parent.Name(set.Name)
}

// Parse ipset save stdout.
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func parseIPSetSave(ipset *IPSet, result string) map[string]*Set {
	sets := make(map[string]*Set)

	// Checks that the parent IPSet family aligns with the ipset that we're saving. This makes ipset.Save() (which is
	// IP family agnostic) behave a bit more like iptables.Save() which is IP family sensitive since different commands
	// give access to different IP families.
	createRelevant := func(pIPSet *IPSet, ipsetName string) bool {
		if pIPSet.isIpv6 {
			return strings.HasPrefix(ipsetName, IPv6SetPrefix)
		}
		return !strings.HasPrefix(ipsetName, IPv6SetPrefix)
	}

	// Save is always in order
	lines := strings.Split(result, "\n")
	skipTilNextCreate := false
	for _, line := range lines {
		content := strings.Split(line, " ")
		switch stmtType := content[0]; stmtType {
		case "create":
			if !createRelevant(ipset, content[1]) {
				skipTilNextCreate = true
				continue
			}
			skipTilNextCreate = false
			sets[content[1]] = &Set{
				Parent:  ipset,
				Name:    content[1],
				Options: scrubInitValFromOptions(content[2:]),
			}
		case "add":
			if skipTilNextCreate {
				continue
			}
			set := sets[content[1]]
			set.Entries = append(set.Entries, &Entry{
				Set:     set,
				Options: content[2:],
			})
		}
	}

	return sets
}

// scrubInitValFromOptions Remove initval options from save set to help reduce the number of unique options and make
// ipset restore work faster. The initval is supposed to help restore the exact same set. However, kube-router modifies
// the sets before it restores it breaking this functionality and causing the restore times to increase significantly.
// So we remove it when we parse the ipset after a save() call.
func scrubInitValFromOptions(options []string) []string {
	for idx, val := range options {
		if val == "initval" {
			return append(options[:idx], options[idx+2:]...)
		}
	}
	return options
}

// Build ipset restore input
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func buildIPSetRestore(ipset *IPSet) string {
	setNames := make([]string, 0, len(ipset.sets))
	for setName := range ipset.sets {
		// we need setNames in some consistent order so that we can unit-test this method has a predictable output:
		setNames = append(setNames, setName)
	}

	sort.Strings(setNames)

	tmpSets := map[string]string{}
	ipSetRestore := &strings.Builder{}
	for _, setName := range setNames {
		set := ipset.sets[setName]
		setOptions := strings.Join(set.Options, " ")

		tmpSetName := tmpSets[setOptions]
		if tmpSetName == "" {
			// create a temporary set per unique set-options:
			//nolint:gosec // we don't use this hash in a sensitive capacity, so we don't care that its weak
			hash := sha1.Sum([]byte("tmp:" + setOptions))
			tmpSetName = tmpIPSetPrefix + base32.StdEncoding.EncodeToString(hash[:10])
			ipSetRestore.WriteString(fmt.Sprintf("create %s %s\n", tmpSetName, setOptions))
			// just in case we are starting up after a crash, we should flush the TMP ipset to be safe if it
			// already existed, so we do not pollute other ipsets:
			ipSetRestore.WriteString(fmt.Sprintf("flush %s\n", tmpSetName))
			tmpSets[setOptions] = tmpSetName
		}

		for _, entry := range set.Entries {
			// add entries to the tmp set:
			ipSetRestore.WriteString(fmt.Sprintf("add %s %s\n", tmpSetName, strings.Join(entry.Options, " ")))
		}

		// now create the actual IPSet (this is a noop if it already exists, because we run with -exists):
		ipSetRestore.WriteString(fmt.Sprintf("create %s %s\n", set.Name, setOptions))

		// now that both exist, we can swap them:
		ipSetRestore.WriteString(fmt.Sprintf("swap %s %s\n", tmpSetName, set.Name))

		// empty the tmp set (which is actually the old one now):
		ipSetRestore.WriteString(fmt.Sprintf("flush %s\n", tmpSetName))
	}

	setsToDestroy := make([]string, 0, len(tmpSets))
	for _, tmpSetName := range tmpSets {
		setsToDestroy = append(setsToDestroy, tmpSetName)
	}
	// need to destroy the sets in a predictable order for unit test!
	sort.Strings(setsToDestroy)
	for _, tmpSetName := range setsToDestroy {
		// finally, destroy the tmp sets.
		ipSetRestore.WriteString(fmt.Sprintf("destroy %s\n", tmpSetName))
	}

	return ipSetRestore.String()
}

// Save the given set, or all sets if none is given to stdout in a format that
// restore can read. The option -file can be used to specify a filename instead
// of stdout.
// save "ipset save" command output to ipset.sets.
func (ipset *IPSet) Save() error {
	stdout, err := ipset.run("save")
	if err != nil {
		return err
	}
	ipset.sets = parseIPSetSave(ipset, stdout)
	return nil
}

// Restore a saved session generated by save. The saved session can be fed from
// stdin or the option -file can be used to specify a filename instead of
// stdin. Please note, existing sets and elements are not erased by restore
// unless specified so in the restore file. All commands are allowed in restore
// mode except list, help, version, interactive mode and restore itself.
// Send formatted ipset.sets into stdin of "ipset restore" command.
func (ipset *IPSet) Restore() error {
	restoreString := buildIPSetRestore(ipset)
	klog.V(3).Infof("ipset (ipv6? %t) restore looks like:\n%s", ipset.isIpv6, restoreString)
	stdin := bytes.NewBufferString(restoreString)
	err := ipset.runWithStdin(stdin, "restore", "-exist")
	if err != nil {
		return err
	}
	return nil
}

// Flush all entries from all sets
func (ipset *IPSet) Flush() error {
	_, err := ipset.run("flush")
	if err != nil {
		return err
	}
	return nil
}

// Get Set by Name.
func (ipset *IPSet) Get(setName string) *Set {
	set, ok := ipset.sets[setName]
	if !ok {
		return nil
	}

	return set
}

// Sets returns all sets from ipset
func (ipset *IPSet) Sets() map[string]*Set {
	return ipset.sets
}
