// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"github.com/cilium/tetragon/pkg/selectors"
)

// ArgPrinter holds information about how to print an argument
// This is used by all sensors to format their arguments
type ArgPrinter struct {
	Ty       int
	UserType int
	Index    int
	MaxData  bool
	Label    string
	Data     bool
}

// KprobeSelectors holds selector state for kprobe entry and return
// This is shared between kprobe and uprobe sensors
type KprobeSelectors struct {
	Entry  *selectors.KernelSelectorState
	Return *selectors.KernelSelectorState
}

// HasMaps tracks which maps are needed for a sensor
// This helps us know what maps to create
type HasMaps struct {
	StackTrace bool
	RateLimit  bool
	FdInstall  bool
	Enforcer   bool
	Override   bool
	SockTrack  bool
	Selector   bool
}

// PendingEventKey is used to identify pending events in retprobes
// We need this to merge enter and return events
type PendingEventKey struct {
	EventId    uint64
	KtimeEnter uint64
}
