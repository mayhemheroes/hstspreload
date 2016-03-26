package hstspreload

import (
	"fmt"
	"strings"
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
	Errors   []string
	Warnings []string
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
		output = fmt.Sprintf(`
		"%s", 
	`, strings.Join(list, `",
		"`))
	} else if len(list) == 1 {
		output = fmt.Sprintf(`"%s"`, list[0])
	}

	return output
}

func (issues Issues) String() string {
	return fmt.Sprintf(`Issues {
	Errors: []string{%s},
	Warnings: []string{%s},
}`,
		formatIssueListForString(issues.Errors),
		formatIssueListForString(issues.Warnings),
	)
}
