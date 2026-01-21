// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/ftrace"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const (
	ListTypeInvalid           = -1
	ListTypeNone              = 0
	ListTypeSyscalls          = 1
	ListTypeGeneratedSyscalls = 2
	ListTypeGeneratedFtrace   = 3

	Is32Bit = 0x80000000
)

var ListTypeTable = map[string]uint32{
	"":                   ListTypeNone,
	"syscalls":           ListTypeSyscalls,
	"generated_syscalls": ListTypeGeneratedSyscalls,
	"generated_ftrace":   ListTypeGeneratedFtrace,
}

// IsList checks if a value specifies a list, and if so it returns it (or nil if list does not exist)
func IsList(val string, lists []v1alpha1.ListSpec) (bool, *v1alpha1.ListSpec) {
	name, found := strings.CutPrefix(val, "list:")
	if !found {
		return false, nil
	}
	for idx := range lists {
		list := &lists[idx]
		if list.Name == name {
			return true, list
		}
	}
	return true, nil
}

// ListTypeFromString converts a string to list type
func ListTypeFromString(s string) int32 {
	typ, ok := ListTypeTable[strings.ToLower(s)]
	if !ok {
		return ListTypeInvalid
	}
	return int32(typ)
}

// IsSyscallListType checks if the list type is a syscall list type
func IsSyscallListType(typ string) bool {
	return ListTypeFromString(typ) == ListTypeSyscalls ||
		ListTypeFromString(typ) == ListTypeGeneratedSyscalls
}

// ValidateList validates a list specification
func ValidateList(list *v1alpha1.ListSpec) (err error) {
	if ListTypeFromString(list.Type) == ListTypeInvalid {
		return fmt.Errorf("invalid list type: %s", list.Type)
	}

	// Generate syscalls list
	if ListTypeFromString(list.Type) == ListTypeGeneratedSyscalls {
		if len(list.Values) != 0 {
			return fmt.Errorf("error generated list '%s' has values", list.Name)
		}
		tmp, err := btf.GetSyscallsList()
		if err != nil {
			return err
		}
		list.Values = append(list.Values, tmp...)
		return nil
	}

	// Generate ftrace list
	if ListTypeFromString(list.Type) == ListTypeGeneratedFtrace {
		if len(list.Values) != 0 {
			return fmt.Errorf("error generated ftrace list '%s' has values", list.Name)
		}
		if list.Pattern == nil || (list.Pattern != nil && *(list.Pattern) == "") {
			return fmt.Errorf("error generated ftrace list '%s' must specify pattern", list.Name)
		}
		list.Values, err = ftrace.ReadAvailFuncs(*(list.Pattern))
		return err
	}

	return nil
}

// PreValidateLists validates all lists in a specification
func PreValidateLists(lists []v1alpha1.ListSpec) (err error) {
	for i := range lists {
		list := &lists[i]

		if list.Validated {
			continue
		}
		err := ValidateList(list)
		if err != nil {
			return err
		}
		list.Validated = true
	}
	return nil
}

// ListReader reads list values
type ListReader struct {
	Lists []v1alpha1.ListSpec
}

// Read reads a list value by name and type
// syscallVal is a function that converts a syscall value string to uint32 ID
func (lr *ListReader) Read(name string, ty uint32, syscallVal func(string) (uint32, error)) ([]uint32, error) {
	list := func() *v1alpha1.ListSpec {
		for idx := range lr.Lists {
			if lr.Lists[idx].Name == name {
				return &lr.Lists[idx]
			}
		}
		return nil
	}()

	if list == nil {
		return []uint32{}, fmt.Errorf("error list '%s' not found", name)
	}
	if !IsSyscallListType(list.Type) {
		return []uint32{}, fmt.Errorf("error list '%s' is not syscall type", name)
	}
	if ty != gt.GenericSyscall64 {
		return []uint32{}, fmt.Errorf("error list '%s' argument type is not syscall64", name)
	}

	var res []uint32
	for _, val := range list.Values {
		id, err := syscallVal(val)
		if err != nil {
			return nil, err
		}
		res = append(res, uint32(id))
	}

	return res, nil
}

// GetSyscallListSymbols gets syscall symbols from a list
// syscallSymbol is a function that converts a syscall value string to symbol name
func GetSyscallListSymbols(list *v1alpha1.ListSpec, syscallSymbol func(string) (string, error)) ([]string, error) {
	if list.Type != "syscalls" {
		return nil, errors.New("unexpected error: getSyscallListSymbols was passed a non-syscall list")
	}

	// syscalls list values requires special interpretation
	ret := make([]string, 0, len(list.Values))
	for _, val := range list.Values {
		symbol, err := syscallSymbol(val)
		if err != nil {
			return nil, fmt.Errorf("failed to parse list element (%s) of syscall list %s: %w", val, list.Name, err)
		}
		ret = append(ret, symbol)
	}

	return ret, nil
}

// GetListSymbols gets symbols from a list
// syscallSymbol is a function that converts a syscall value string to symbol name
func GetListSymbols(list *v1alpha1.ListSpec, syscallSymbol func(string) (string, error)) ([]string, error) {
	switch list.Type {
	case "syscalls":
		return GetSyscallListSymbols(list, syscallSymbol)
	default:
		return list.Values, nil
	}
}
