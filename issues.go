package hstspreload

import (
	"fmt"
	"strings"
)

type Issues struct {
	Errors   []string
	Warnings []string
}

func NewIssues() Issues {
	return Issues{
		Errors:   []string{},
		Warnings: []string{},
	}
}

func (issues Issues) AddError(err string) Issues {
	return Issues{
		Errors:   append(issues.Errors, err),
		Warnings: issues.Warnings,
	}
}

func (issues Issues) AddWarning(warning string) Issues {
	return Issues{
		Errors:   issues.Errors,
		Warnings: append(issues.Warnings, warning),
	}
}

func (issues Issues) AddUniqueError(uniqueErr string) Issues {
	for _, err := range issues.Errors {
		if err == uniqueErr {
			return issues
		}
	}
	return issues.AddError(uniqueErr)
}

func (issues Issues) AddUniqueWarning(uniqueWarning string) Issues {
	for _, warning := range issues.Warnings {
		if warning == uniqueWarning {
			return issues
		}
	}
	return issues.AddWarning(uniqueWarning)
}

func CombineIssues(issues1 Issues, issues2 Issues) Issues {
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
	errors: []string{%s},
	warnings: []string{%s},
}`,
		formatIssueListForString(issues.Errors),
		formatIssueListForString(issues.Warnings),
	)
}
