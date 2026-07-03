//go:build signing

package handler

// JSONMarshalFnForTest allows tests to inject a failing JSON marshal function.
var JSONMarshalFnForTest = &jsonMarshalFn

// RsaSignFnForTest allows tests to inject a failing signing function.
var RsaSignFnForTest = &rsaSignFn
