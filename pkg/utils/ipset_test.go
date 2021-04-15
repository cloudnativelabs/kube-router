package utils

import "testing"

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
			name: "swap-two-sets",
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
				}},
			},
			want: "create TMP-GOAQNXK75HLZIRC5 hash:ip yolo things 12345\n" +
				"add TMP-GOAQNXK75HLZIRC5 1.2.3.4\n" +
				"create foo hash:ip yolo things 12345\n" +
				"swap TMP-GOAQNXK75HLZIRC5 foo\n" +
				"destroy TMP-GOAQNXK75HLZIRC5\n" +
				"create TMP-5IF7SUJ4ODWBSS75 hash:ip lol\n" +
				"add TMP-5IF7SUJ4ODWBSS75 4.4.4.4\n" +
				"add TMP-5IF7SUJ4ODWBSS75 8.8.8.8\n" +
				"create google-dns-servers hash:ip lol\n" +
				"swap TMP-5IF7SUJ4ODWBSS75 google-dns-servers\n" +
				"destroy TMP-5IF7SUJ4ODWBSS75\n",
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
