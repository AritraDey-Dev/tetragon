// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4

	// Map size constants - these could be fine tuned if features use too much kernel memory
	StackTraceMapMaxEntries    = 32768
	RatelimitMapMaxEntries     = 32768
	FdInstallMapMaxEntries     = 32000
	EnforcerMapMaxEntries      = 32768
	OverrideMapMaxEntries      = 32768
	SleepableOffloadMaxEntries = 32768
	SocktrackMapMaxEntries     = 32000

	MaxStringSize = 4096
)

func KprobeCharBufErrorToString(e int32) string {
	switch e {
	case CharBufErrorENOMEM:
		return "CharBufErrorENOMEM"
	case CharBufErrorTooLarge:
		return "CharBufErrorBufTooLarge"
	case CharBufErrorPageFault:
		return "CharBufErrorPageFault"
	}
	return "CharBufErrorUnknown"
}
