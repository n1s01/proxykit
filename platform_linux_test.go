//go:build linux

package proxykit

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseProcNetRoute(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wg0	00000000	00000000	0001	0	0	50	00000000	0	0	0
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0100000A	0003	0	0	100	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	100	00FFFFFF	0	0	0
down0	00000000	01000000	0002	0	0	1	00000000	0	0	0
`
	index := map[string]int{"wg0": 9, "wlan0": 3, "eth0": 2, "down0": 5}
	got := parseProcNetRoute(strings.NewReader(table), func(name string) (int, bool) {
		i, ok := index[name]
		return i, ok
	})
	// The tunnel ranks first here; physicalCandidate removes it later.
	if want := []int{9, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
