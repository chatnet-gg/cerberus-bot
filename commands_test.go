package main

import (
	"reflect"
	"testing"
)

func TestSplitPageArg(t *testing.T) {
	cases := []struct {
		in     []string
		want   []string
		offset int
	}{
		{[]string{"foo"}, []string{"foo"}, 0},
		{[]string{"foo", "-11"}, []string{"foo"}, 10},
		{[]string{"*", "-21"}, []string{"*"}, 20},
		{[]string{"-3"}, []string{}, 2},
		{[]string{"two", "words", "-2"}, []string{"two", "words"}, 1},
		{[]string{"-1"}, []string{}, 0},
		{[]string{"foo", "-0"}, []string{"foo", "-0"}, 0}, // not a page argument
		{[]string{"foo", "bar"}, []string{"foo", "bar"}, 0},
	}
	for _, c := range cases {
		got, off := splitPageArg(append([]string(nil), c.in...))
		if len(got) == 0 && len(c.want) == 0 {
			got = []string{}
		}
		if !reflect.DeepEqual(got, c.want) || off != c.offset {
			t.Errorf("splitPageArg(%v) = %v, %d; want %v, %d", c.in, got, off, c.want, c.offset)
		}
	}
}

func TestNextPageHint(t *testing.T) {
	if h := nextPageHint("*", 0, kcheckResultLimit-1); h != "" {
		t.Errorf("a short page must have no hint, got %q", h)
	}
	if h := nextPageHint("*", 0, kcheckResultLimit); h != "For next set of entries enter: KCHECK * -11" {
		t.Errorf("first full page hint = %q", h)
	}
	if h := nextPageHint("bad nick", 10, kcheckResultLimit); h != "For next set of entries enter: KCHECK bad nick -21" {
		t.Errorf("second page hint = %q", h)
	}
}

func TestChannelNameRe(t *testing.T) {
	for _, ok := range []string{"#chatnet", "#a", "#Some-Channel_1", "#ops!"} {
		if !channelNameRe.MatchString(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "chatnet", "#", "#two words", "#a,#b", "#bell\x07", "&local", "#" + string(make([]byte, 60))} {
		if channelNameRe.MatchString(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
}
