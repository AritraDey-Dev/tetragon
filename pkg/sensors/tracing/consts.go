// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import "github.com/cilium/tetragon/pkg/sensors/tracing/common"

// Constants for backward compatibility
const (
	CharBufErrorENOMEM      = common.CharBufErrorENOMEM
	CharBufErrorPageFault   = common.CharBufErrorPageFault
	CharBufErrorTooLarge    = common.CharBufErrorTooLarge
	CharBufSavedForRetprobe = common.CharBufSavedForRetprobe

	stackTraceMapMaxEntries    = common.StackTraceMapMaxEntries
	ratelimitMapMaxEntries     = common.RatelimitMapMaxEntries
	fdInstallMapMaxEntries     = common.FdInstallMapMaxEntries
	enforcerMapMaxEntries      = common.EnforcerMapMaxEntries
	overrideMapMaxEntries      = common.OverrideMapMaxEntries
	sleepableOffloadMaxEntries = common.SleepableOffloadMaxEntries
	socktrackMapMaxEntries     = common.SocktrackMapMaxEntries
)
