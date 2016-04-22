package hstspreload

import (
	"fmt"
)

// The Issues struct encapsulates a set of errors and warnings.
// By convention:
//
// - Errors contains a list of errors that will prevent preloading.
//
// - Warnings contains a list errors that are a good idea to fix,
// but are okay for preloading.
//
// - Warning and errors will state at which level the issue occurred (e.g. header syntax, preload requirement checking, HTTP response checking, domain checking).
//
// - If Issues is returned from a Check____() function without any errors
// or warnings, it means that the function passed all checks.
//
// - The list of errors is not guaranteed to be exhaustive. In
// particular, fixing a given error (e.g. "could not connect to
// server") may bring another error to light (e.g. "HSTS header was
// not found").
type Issues struct {
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// NewIssues constructs a new, empty Issues struct.
func NewIssues() Issues {
	return Issues{
		Errors:   []string{},
		Warnings: []string{},
	}
}

func (issues Issues) addErrorf(format string, args ...interface{}) Issues {
	formattedError := fmt.Sprintf(format, args...)
	return Issues{
		Errors:   append(issues.Errors, formattedError),
		Warnings: issues.Warnings,
	}
}

func (issues Issues) addWarningf(format string, args ...interface{}) Issues {
	formattedWarning := fmt.Sprintf(format, args...)
	return Issues{
		Errors:   issues.Errors,
		Warnings: append(issues.Warnings, formattedWarning),
	}
}

func (issues Issues) addUniqueErrorf(format string, args ...interface{}) Issues {
	formattedError := fmt.Sprintf(format, args...)
	for _, err := range issues.Errors {
		if err == formattedError {
			return issues
		}
	}
	return Issues{
		Errors:   append(issues.Errors, formattedError),
		Warnings: issues.Warnings,
	}
}

func (issues Issues) addUniqueWarningf(format string, args ...interface{}) Issues {
	formattedWarning := fmt.Sprintf(format, args...)
	for _, warning := range issues.Warnings {
		if warning == formattedWarning {
			return issues
		}
	}
	return Issues{
		Errors:   issues.Errors,
		Warnings: append(issues.Warnings, formattedWarning),
	}
}

func combineIssues(issues1 Issues, issues2 Issues) Issues {
	return Issues{
		Errors:   append(issues1.Errors, issues2.Errors...),
		Warnings: append(issues1.Warnings, issues2.Warnings...),
	}
}

func formatIssueListForString(list []string) string {
	output := ""
	if len(list) > 1 {
		for _, s := range list {
			output += fmt.Sprintf(
				"\n		%#v,",
				s,
			)
		}
		output += "\n	"
	} else if len(list) == 1 {
		output = fmt.Sprintf(`%#v`, list[0])
	}

	return output
}

// GoString formats issues with multiple lines and indentation.
// This is mainly used to provide output for unit tests in this project
// that can be pasted back into the relevant unit tess.
func (issues Issues) GoString() string {
	return fmt.Sprintf(`Issues{
	Errors:   []string{%s},
	Warnings: []string{%s},
}`,
		formatIssueListForString(issues.Errors),
		formatIssueListForString(issues.Warnings),
	)
}

// MakeSlices replaces empty Errors or Warnings with make([]string, 0)
//
// When converting Issues to JSON, it may be desirable for empty errors
// to be marshalled as `[]` instead of `null`. To ensure this, call
// MakeSlices() on the Issues first.
func MakeSlices(issues Issues) Issues {
	if len(issues.Errors) == 0 {
		issues.Errors = make([]string, 0)
	}
	if len(issues.Warnings) == 0 {
		issues.Warnings = make([]string, 0)
	}
	return issues
}
