//go:build signing

package handler

// JsonMarshalFnForTest allows tests to inject a failing JSON marshal function.
var JsonMarshalFnForTest = &jsonMarshalFn

// RsaSignFnForTest allows tests to inject a failing signing function.
var RsaSignFnForTest = &rsaSignFn
