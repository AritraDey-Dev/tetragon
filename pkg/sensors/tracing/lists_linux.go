// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// Constants for backward compatibility
const (
	ListTypeInvalid           = common.ListTypeInvalid
	ListTypeNone              = common.ListTypeNone
	ListTypeSyscalls          = common.ListTypeSyscalls
	ListTypeGeneratedSyscalls = common.ListTypeGeneratedSyscalls
	ListTypeGeneratedFtrace   = common.ListTypeGeneratedFtrace

	Is32Bit = common.Is32Bit
)

// Wrapper functions for backward compatibility
func isList(val string, lists []v1alpha1.ListSpec) (bool, *v1alpha1.ListSpec) {
	return common.IsList(val, lists)
}

func listTypeFromString(s string) int32 {
	return common.ListTypeFromString(s)
}

func isSyscallListType(typ string) bool {
	return common.IsSyscallListType(typ)
}

func validateList(list *v1alpha1.ListSpec) error {
	return common.ValidateList(list)
}

func preValidateLists(lists []v1alpha1.ListSpec) error {
	return common.PreValidateLists(lists)
}

type listReader struct {
	lists []v1alpha1.ListSpec
}

func (lr *listReader) Read(name string, ty uint32) ([]uint32, error) {
	commonReader := common.ListReader{Lists: lr.lists}
	return commonReader.Read(name, ty, func(val string) (uint32, error) {
		id, err := SyscallVal(val).ID()
		if err != nil {
			return 0, err
		}
		return uint32(id), nil
	})
}

func getSyscallListSymbols(list *v1alpha1.ListSpec) ([]string, error) {
	return common.GetSyscallListSymbols(list, func(val string) (string, error) {
		return SyscallVal(val).Symbol()
	})
}

func getListSymbols(list *v1alpha1.ListSpec) ([]string, error) {
	return common.GetListSymbols(list, func(val string) (string, error) {
		return SyscallVal(val).Symbol()
	})
}
