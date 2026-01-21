// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	ebtf "github.com/cilium/ebpf/btf"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// Wrapper functions for backward compatibility

func formatBTFPath(resolvePath string) ([]string, error) {
	return common.FormatBTFPath(resolvePath)
}

func addPaddingOnNestedPtr(ty ebtf.Type, path []string) []string {
	return common.AddPaddingOnNestedPtr(ty, path)
}

func hasCurrentTaskSource(arg *v1alpha1.KProbeArg) bool {
	return common.HasCurrentTaskSource(arg)
}

func hasPtRegsSource(arg *v1alpha1.KProbeArg) bool {
	return common.HasPtRegsSource(arg)
}

func resolveBTFType(arg *v1alpha1.KProbeArg, ty ebtf.Type) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	return common.ResolveBTFType(arg, ty)
}

func resolveUserBTFArg(arg *v1alpha1.KProbeArg, btfPath string) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	return common.ResolveUserBTFArg(arg, btfPath)
}

func resolveBTFArg(hook string, arg *v1alpha1.KProbeArg, tp bool) (*ebtf.Type, [api.MaxBTFArgDepth]api.ConfigBTFArg, error) {
	return common.ResolveBTFArg(hook, arg, tp)
}

func resolveBTFPath(btfArg *[api.MaxBTFArgDepth]api.ConfigBTFArg, rootType ebtf.Type, path []string) (*ebtf.Type, error) {
	return common.ResolveBTFPath(btfArg, rootType, path)
}

func findTypeFromBTFType(arg *v1alpha1.KProbeArg, btfType *ebtf.Type) int {
	return common.FindTypeFromBTFType(arg, btfType)
}

func pathArgWarning(index uint32, ty int, s []v1alpha1.KProbeSelector) {
	common.PathArgWarning(index, ty, s)
}
