package hstspreload

import (
	"fmt"
	"strings"
)

type Issues struct {
	errors   []string
	warnings []string
}

func NewIssues() Issues {
	return Issues{
		errors:   []string{},
		warnings: []string{},
	}
}

func (issues Issues) AddError(err string) Issues {
	return Issues{
		errors:   append(issues.errors, err),
		warnings: issues.warnings,
	}
}

func (issues Issues) AddWarning(warning string) Issues {
	return Issues{
		errors:   issues.errors,
		warnings: append(issues.warnings, warning),
	}
}

func CombineIssues(issues1 Issues, issues2 Issues) Issues {
	return Issues{
		errors:   append(issues1.errors, issues2.errors...),
		warnings: append(issues1.warnings, issues2.warnings...),
	}
}

// Includes ordering of errors and warnings.
func issuesEqual(issues1 Issues, issues2 Issues) bool {
	// reflect.DeepEqual seems to have false negatives, so we don't use it.

	if len(issues1.errors) != len(issues2.errors) {
		return false
	}

	if len(issues1.warnings) != len(issues2.warnings) {
		return false
	}

	for e := range issues1.errors {
		if issues1.errors[e] != issues2.errors[e] {
			return false
		}
	}

	for w := range issues1.warnings {
		if issues1.warnings[w] != issues2.warnings[w] {
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
	errors: []string{%s},
	warnings: []string{%s},
}`,
		formatIssueListForString(issues.errors),
		formatIssueListForString(issues.warnings),
	)
}
