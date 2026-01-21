// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"errors"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metrics/enforcermetrics"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// EnforcerMaps creates enforcer maps for a program
func EnforcerMaps(load *program.Program) []*program.Map {
	edm := program.MapBuilderPolicy(EnforcerDataMapName, load)
	edm.SetMaxEntries(EnforcerMapMaxEntries)
	return []*program.Map{
		edm,
		program.MapBuilderPolicy(enforcermetrics.EnforcerMissedMapName, load),
	}
}

// EnforcerMapsUser creates user enforcer maps for a program
func EnforcerMapsUser(load *program.Program) []*program.Map {
	edm := program.MapUserPolicy(EnforcerDataMapName, load)
	edm.SetMaxEntries(EnforcerMapMaxEntries)
	return []*program.Map{
		edm,
		program.MapUserPolicy(enforcermetrics.EnforcerMissedMapName, load),
	}
}

// SelectOverrideMethod selects proper override method based on configuration and spec options
func SelectOverrideMethod(overrideMethod OverrideMethod, hasSyscall bool) (OverrideMethod, error) {
	switch overrideMethod {
	case OverrideMethodDefault:
		// by default, first try OverrideReturn and if this does not work try fmod_ret
		if bpf.HasOverrideHelper() {
			overrideMethod = OverrideMethodReturn
		} else if bpf.HasModifyReturnSyscall() {
			overrideMethod = OverrideMethodFmodRet
		} else {
			return OverrideMethodInvalid, errors.New("no override helper or mod_ret support: cannot load enforcer")
		}
	case OverrideMethodReturn:
		if !bpf.HasOverrideHelper() {
			return OverrideMethodInvalid, errors.New("option override return set, but it is not supported")
		}
	case OverrideMethodFmodRet:
		if !bpf.HasModifyReturn() || (hasSyscall && !bpf.HasModifyReturnSyscall()) {
			return OverrideMethodInvalid, errors.New("option fmod_ret set, but it is not supported")
		}
	}

	return overrideMethod, nil
}
