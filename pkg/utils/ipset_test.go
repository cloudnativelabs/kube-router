package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_buildIPSetRestore(t *testing.T) {
	type args struct {
		ipset *IPSet
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "simple-restore",
			args: args{
				ipset: &IPSet{Sets: map[string]*Set{
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
			if got := buildIPSetRestore(tt.args.ipset); got != tt.want {
				t.Errorf("buildIPSetRestore() = %v, want %v", got, tt.want)
			}
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
