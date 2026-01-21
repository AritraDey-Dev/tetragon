// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/sensors/tracing/common"
)

// Constants and errors for backward compatibility
const (
	TpMaxMessageLen = common.TpMaxMessageLen
	TpMinMessageLen = common.TpMinMessageLen
)

var (
	ErrMsgSyntaxLong   = common.ErrMsgSyntaxLong
	ErrMsgSyntaxShort  = common.ErrMsgSyntaxShort
	ErrMsgSyntaxEmpty  = common.ErrMsgSyntaxEmpty
	ErrMsgSyntaxEscape = common.ErrMsgSyntaxEscape
)

func getPolicyMessage(message string) (string, error) {
	return common.GetPolicyMessage(message)
}
