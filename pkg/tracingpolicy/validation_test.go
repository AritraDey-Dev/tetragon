// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestKprobeValidationReturnWithoutArg(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
`
	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ReturnArg not specified with Return=true.")
}

func testUprobeValidationSymbolsAddrsOffsets(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
`
	if withSymbol {
		crd += "    symbols: [\"test_3\"]\n"
	}
	if withAdrr {
		crd += "    addrs: [0x985256]\n"
	}
	if withOff {
		crd += "    offsets: [0x9156366]\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "symbols, addrs or offsets defined")
}

func TestUprobeValidationSymbolsAddrsOffsets(t *testing.T) {
	t.Run("SymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, true)
	})

	t.Run("SymbolAddr", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, false)
	})

	t.Run("SymbolOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, false, true)
	})

	t.Run("AddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, false, true, true)
	})
}

func TestUprobeValidationReturnWithoutArg(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_3"
    return: true
`

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ReturnArg not specified with Return=true.")
}

func testUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_1"
    selectors:
    - matchActions:
      - action: Override
`
	if withSymbol {
		crd += "        argNewSymbol: \"test_3\"\n"
	}
	if withAdrr {
		crd += "        argNewAddr: 0x985256\n"
	}
	if withOff {
		crd += "        argNewOffset: 0x9156366\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "argNewSymbol, argNewAddr or argNewOffset defined")
}

func TestUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T) {
	t.Run("NewSymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, true)
	})

	t.Run("NewSymbolAddr", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, false)
	})

	t.Run("NewSymbolOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, false, true)
	})

	t.Run("NewAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, false, true, true)
	})
}

func TestMatchCmdArgsYAML(t *testing.T) {
	policy, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: match-command-arguments
spec:
  kprobes:
  - call: security_file_permission
    selectors:
    - matchCmdArgs:
      - index: 0
        operator: Equal
        values:
        - -flag1=value1
      - index: 1
        operator: Prefix
        values:
        - /my/path
`)
	require.NoError(t, err)

	selectors := policy.TpSpec().KProbes[0].Selectors
	require.Equal(t, []v1alpha1.CmdArgSelector{
		{
			Index:    0,
			Operator: "Equal",
			Values:   []string{"-flag1=value1"},
		},
		{
			Index:    1,
			Operator: "Prefix",
			Values:   []string{"/my/path"},
		},
	}, selectors[0].MatchCmdArgs)
}

func TestMatchCmdArgsOperatorValidation(t *testing.T) {
	_, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: match-command-arguments
spec:
  kprobes:
  - call: security_file_permission
    selectors:
    - matchCmdArgs:
      - index: 0
        operator: Invalid
        values:
        - value
`)
	require.Error(t, err)
}

// kprobe data is read from somewhere other than the traced function's
// arguments, so there is no argument position to point at. Requiring an index
// on it forced everyone to write a meaningless "index: 0".
func TestKprobeDataIndexOptional(t *testing.T) {
	policy := func(indexLine string) string {
		return `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "auid-filter"
spec:
  kprobes:
  - call: "sys_setuid"
    syscall: true
    args:
    - index: 0
      type: int
    data:
    - type: uint32
` + indexLine + `      source: current_task
      resolve: "loginuid.val"
    selectors:
    - matchData:
      - args: [0]
        operator: "NotEqual"
        values: ["1000"]
`
	}

	t.Run("without index", func(t *testing.T) {
		_, err := FromYAML(policy(""))
		require.NoError(t, err)
	})

	// Policies written while index was required must keep working.
	t.Run("with index, for backwards compatibility", func(t *testing.T) {
		_, err := FromYAML(policy("      index: 0\n"))
		require.NoError(t, err)
	})

	// Arguments still need one: index 0 is a perfectly plausible argument
	// position, so silently defaulting there would trace the wrong argument.
	t.Run("args still require an index", func(t *testing.T) {
		_, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "arg-without-index"
spec:
  kprobes:
  - call: "sys_setuid"
    syscall: true
    args:
    - type: int
`)
		require.Error(t, err)
		require.Contains(t, err.Error(), "index in body is required")
	})
}

// KProbeData duplicates KProbeArg's fields so that index can be optional on
// one and required on the other. Catch the two drifting apart.
func TestKprobeDataMatchesKprobeArgFields(t *testing.T) {
	jsonFields := func(typ reflect.Type) []string {
		var out []string
		for i := range typ.NumField() {
			tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			out = append(out, tag)
		}
		sort.Strings(out)
		return out
	}

	arg := jsonFields(reflect.TypeOf(v1alpha1.KProbeArg{}))
	data := jsonFields(reflect.TypeOf(v1alpha1.KProbeData{}))
	require.Equal(t, arg, data,
		"KProbeArg and KProbeData must carry the same fields; update KProbeData and its KProbeArg method")
}
