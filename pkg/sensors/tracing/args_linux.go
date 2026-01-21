// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"io"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

type argPrinter struct {
	ty       int
	userType int
	index    int
	maxData  bool
	label    string
	data     bool
}

// Wrapper functions for backward compatibility

func argReturnCopy(meta int) bool {
	return common.ArgReturnCopy(meta)
}

func getMetaValue(arg *v1alpha1.KProbeArg) (int, error) {
	return common.GetMetaValue(arg, common.HasCurrentTaskSource(arg), common.HasPtRegsSource(arg))
}

func getTracepointMetaValue(arg *v1alpha1.KProbeArg) int {
	return common.GetTracepointMetaValue(arg)
}

func getArg(r *bytes.Reader, a argPrinter) api.MsgGenericKprobeArg {
	// Convert argPrinter to common.ArgPrinter
	commonArg := common.ArgPrinter{
		Ty:       a.ty,
		UserType: a.userType,
		Index:    a.index,
		MaxData:  a.maxData,
		Label:    a.label,
		Data:     a.data,
	}
	return common.GetArg(r, commonArg)
}

// parseString is a wrapper for common.ParseString
func parseString(r io.Reader) (string, error) {
	return common.ParseString(r)
}

// ReadArgBytes is a wrapper for common.ReadArgBytes
func ReadArgBytes(r *bytes.Reader, index int, hasMaxData bool) (*api.MsgGenericKprobeArgBytes, error) {
	return common.ReadArgBytes(r, index, hasMaxData)
}
