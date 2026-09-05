// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package events_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coredhcp/coredhcp/events"
)

func TestFamilyString(t *testing.T) {
	tests := []struct {
		name string
		f    events.Family
		want string
	}{
		{name: "v4", f: events.FamilyV4, want: "DHCPv4"},
		{name: "v6", f: events.FamilyV6, want: "DHCPv6"},
		// out-of-range value to exercise the default branch
		{name: "unknown", f: events.Family(9), want: "DHCP?"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.f.String())
		})
	}
}

func TestOutcomeString(t *testing.T) {
	tests := []struct {
		name string
		o    events.Outcome
		want string
	}{
		{name: "replied", o: events.OutcomeReplied, want: "replied"},
		{name: "dropped", o: events.OutcomeDropped, want: "dropped"},
		{name: "no reply", o: events.OutcomeNoReply, want: "no reply"},
		{name: "parse error", o: events.OutcomeParseError, want: "parse error"},
		{name: "unsupported", o: events.OutcomeUnsupported, want: "unsupported"},
		{name: "send error", o: events.OutcomeSendError, want: "send error"},
		// out-of-range value to exercise the default branch
		{name: "unknown", o: events.Outcome(99), want: "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.o.String())
		})
	}
}

func TestReplyPathString(t *testing.T) {
	tests := []struct {
		name string
		p    events.ReplyPath
		want string
	}{
		{name: "none", p: events.PathNone, want: "-"},
		{name: "unicast", p: events.PathUnicast, want: "unicast"},
		{name: "broadcast", p: events.PathBroadcast, want: "broadcast"},
		{name: "layer2", p: events.PathLayer2, want: "layer2"},
		// out-of-range value to exercise the default branch
		{name: "unknown", p: events.ReplyPath(99), want: "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.p.String())
		})
	}
}
