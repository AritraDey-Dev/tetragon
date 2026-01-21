// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kprobe

import (
	lru "github.com/hashicorp/golang-lru/v2"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// KprobeSelectors holds selector state for kprobe entry and return
type KprobeSelectors struct {
	Entry  *selectors.KernelSelectorState
	Return *selectors.KernelSelectorState
}

// KprobeLoadArgs holds the arguments needed to load a kprobe program
type KprobeLoadArgs struct {
	Selectors KprobeSelectors
	Retprobe  bool
	Syscall   bool
	Config    *api.EventConfig
}

// PendingEventKey is used to identify pending events in retprobes
type PendingEventKey struct {
	EventId    uint64
	KtimeEnter uint64
}

// GenericKprobeData holds sensor-specific data needed when processing events
type GenericKprobeData struct {
	// stackTraceMap reference is needed when retrieving stack traces from
	// userspace when receiving events containing stacktrace IDs
	StackTraceMap *program.Map
}

// GenericKprobe holds information about a generic kprobe
type GenericKprobe struct {
	LoadArgs          KprobeLoadArgs
	ArgSigPrinters    []common.ArgPrinter
	ArgReturnPrinters []common.ArgPrinter
	FuncName          string
	Instance          int

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// the retprobe_id (thread_id) and the enter ktime as the key.
	PendingEvents *lru.Cache[PendingEventKey, PendingEvent[*tracing.MsgGenericKprobeUnix]]

	TableID idtable.EntryID

	// for kprobes that have a GetUrl or DnsLookup action, we store the table of arguments.
	ActionArgs idtable.Table

	// policyName is the name of the policy that this tracepoint belongs to
	PolicyName string

	// message field of the Tracing Policy
	Message string

	// tags field of the Tracing Policy
	Tags []string

	// is there override defined for the kprobe
	HasOverride bool

	// is there selector defined for the kprobe
	HasSelector bool

	// sensor specific data that we need when we process event, so it's
	// unique for each kprobeEntry when we use single kprobes and it's
	// ont global instance when we use kprobe multi
	Data *GenericKprobeData

	// Does this kprobe is using stacktraces? Note that as specified in the
	// above data field comment, the map is global for multikprobe and unique
	// for each kprobe when using single kprobes.
	HasStackTrace bool

	CustomHandler eventhandler.Handler
}

// PendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type PendingEvent[T evArgsRetriever] struct {
	Ev          T
	ReturnEvent bool
}

// evArgsRetriever is an interface for events that can retrieve their arguments
// This is used for merging enter and return events in retprobes
type evArgsRetriever interface {
	GetArgs() *[]api.MsgGenericKprobeArg
	// This constraint allows us to return nil from methods
	*tracing.MsgGenericKprobeUnix | *tracing.MsgGenericUprobeUnix
}

func (g *GenericKprobe) SetID(id idtable.EntryID) {
	g.TableID = id
}
