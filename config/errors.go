// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package config

import (
	"fmt"
)

// Error is an error type returned upon configuration errors.
type Error struct {
	err error
}

// ErrorFromString returns an Error from the given format string and arguments.
func ErrorFromString(format string, args ...any) *Error {
	return &Error{
		err: fmt.Errorf(format, args...),
	}
}

// ErrorFromError returns an Error wrapping the given error object.
func ErrorFromError(err error) *Error {
	return &Error{
		err: err,
	}
}

func (ce Error) Error() string {
	return fmt.Sprintf("error parsing config: %v", ce.err)
}

// Unwrap returns the underlying error, so errors.Is and errors.As see
// through the config wrapper.
func (ce Error) Unwrap() error {
	return ce.err
}
