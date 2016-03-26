package hstspreload

import (
	"fmt"
	"strings"
)

// The Issues struct encapsulates a set of errors and warnings.
// By convention:
//
//   - `Errors` contains a list of errors that will prevent preloading.
//   - `Warnings` contains a list errors that are a good idea to fix,
//     but are okay for preloading.
//   - Warning and errors will state at which level the issue occurred:
//     - Header syntax
//     - Preload requirement checking
//     - HTTP response checking
//     - Domain checking
//   - If `Issues` is returned from a Check____() function without any errors
//     or warnings, it means that the function passed all checks.
//   - The list of errors is not guaranteed to be exhaustive. In
//     particular, fixing a given error (e.g. "could not connect to
//     server") may bring another error to light (e.g. "HSTS header was
//     not found").
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

func (issues Issues) addError(err string) Issues {
	return Issues{
		Errors:   append(issues.Errors, err),
		Warnings: issues.Warnings,
	}
}

func (issues Issues) addWarning(warning string) Issues {
	return Issues{
		Errors:   issues.Errors,
		Warnings: append(issues.Warnings, warning),
	}
}

func (issues Issues) addUniqueError(uniqueErr string) Issues {
	for _, err := range issues.Errors {
		if err == uniqueErr {
			return issues
		}
	}
	return issues.addError(uniqueErr)
}

func (issues Issues) addUniqueWarning(uniqueWarning string) Issues {
	for _, warning := range issues.Warnings {
		if warning == uniqueWarning {
			return issues
		}
	}
	return issues.addWarning(uniqueWarning)
}

func combineIssues(issues1 Issues, issues2 Issues) Issues {
	return Issues{
		Errors:   append(issues1.Errors, issues2.Errors...),
		Warnings: append(issues1.Warnings, issues2.Warnings...),
	}
}

// Includes ordering of errors and warnings.
func issuesEqual(issues1 Issues, issues2 Issues) bool {
	// reflect.DeepEqual seems to have false negatives, so we don't use it.

	if len(issues1.Errors) != len(issues2.Errors) {
		return false
	}

	if len(issues1.Warnings) != len(issues2.Warnings) {
		return false
	}

	for e := range issues1.Errors {
		if issues1.Errors[e] != issues2.Errors[e] {
			return false
		}
	}

	for w := range issues1.Warnings {
		if issues1.Warnings[w] != issues2.Warnings[w] {
			return false
		}
	}

	return true
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
