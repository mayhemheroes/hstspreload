package hstspreload

import (
	"fmt"
	"reflect"
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
func AreIssuesEqual(issues1 Issues, issues2 Issues) bool {
	return reflect.DeepEqual(issues1, issues2)
}

func (issues Issues) HasError() bool {
	return len(issues.errors) > 0
}

func (issues Issues) String() string {
	errorsString := ""
	if len(issues.errors) > 0 {
		errorsString = fmt.Sprintf(`"%s"`, strings.Join(issues.errors, "\", \""))
	}

	warningsString := ""
	if len(issues.warnings) > 0 {
		warningsString = fmt.Sprintf(`"%s"`, strings.Join(issues.warnings, "\", \""))
	}

	return fmt.Sprintf(`Issues {
	errors: string[]{%s},
	warnings: string[]{%s},
}`,
		errorsString,
		warningsString,
	)
}

// func (issues Issues) String() string {
//   sections := []string{}

//   if len(issues.errors) > 0  {
//     if len(issues.errors) == 1 {
//       sections = append(sections, fmt.Sprintf("Error: %s", strings.Join(issues.errors, "][")))
//     } else {
//       sections = append(sections, fmt.Sprintf("Errors: [%s]", strings.Join(issues.errors, "][")))
//     }
//   }

//   if len(issues.warnings) > 0  {
//     if len(issues.warnings) == 1 {
//       sections = append(sections, fmt.Sprintf("Warning: %s", strings.Join(issues.warnings, "][")))
//     } else {
//       sections = append(sections, fmt.Sprintf("Warnings: [%s]", strings.Join(issues.warnings, "][")))
//     }
//   }

//   if len(sections) == 0 {
//     return "No issues."
//   } else {
//     return strings.Join(sections, ", ")
//   }
// }
