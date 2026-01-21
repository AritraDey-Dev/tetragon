// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import "github.com/cilium/tetragon/pkg/sensors/tracing/common"

// Constants and functions for backward compatibility
const maxStringSize = common.MaxStringSize

var errParseStringSize = common.ErrParseStringSize

func kprobeCharBufErrorToString(e int32) string {
	return common.KprobeCharBufErrorToString(e)
}
