// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPolicyMessage(t *testing.T) {
	msg, err := GetPolicyMessage("")
	require.Empty(t, msg)
	require.Equal(t, err, ErrMsgSyntaxEmpty)

	msg, err = GetPolicyMessage("a")
	require.Empty(t, msg)
	require.Equal(t, err, ErrMsgSyntaxShort)

	msg, err = GetPolicyMessage("test")
	require.NoError(t, err)
	require.Equal(t, "test", msg)

	msg, err = GetPolicyMessage(strings.Repeat("a", TpMaxMessageLen+1))
	require.Equal(t, err, ErrMsgSyntaxLong)
	require.Len(t, msg, TpMaxMessageLen)
}
