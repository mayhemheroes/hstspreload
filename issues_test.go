package hstspreload

import (
	"runtime"
	"strings"
	"testing"
)

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

// Based on https://golang.org/src/testing/testing.go
func getCaller(levelsUp int) (file string, line int) {
	_, file, line, ok := runtime.Caller(levelsUp + 1)
	if ok {
		// Truncate file name at last file name separator.
		if index := strings.LastIndex(file, "/"); index >= 0 {
			file = file[index+1:]
		} else if index = strings.LastIndex(file, "\\"); index >= 0 {
			file = file[index+1:]
		}
	} else {
		file = "???"
		line = 1
	}
	return file, line
}

func expectIssuesEqualImpl(t *testing.T, actual Issues, expected Issues, levelsUp int) {
	file, line := getCaller(levelsUp + 1)
	if !issuesEqual(actual, expected) {
		t.Errorf(`Issues should be equal. (%s:%d)

## Actual

%v

## Expected

%v

`, file, line, actual, expected)
	}
}

func expectIssuesNotEqual(t *testing.T, actual Issues, expected Issues) {
	file, line := getCaller(1)
	if issuesEqual(actual, expected) {
		t.Errorf(`Issues should not be equal. (%s:%d)

## Actual

%v

## (Not) Expected

%v

`, file, line, actual, expected)
	}
}

func expectIssuesEqual(t *testing.T, actual Issues, expected Issues) {
	expectIssuesEqualImpl(t, actual, expected, 1)
}

// This function name is more clear than comparing whether we're "equal" to empty.
func expectIssuesEmpty(t *testing.T, actual Issues) {
	expectIssuesEqualImpl(t, actual, NewIssues(), 1)
}

func TestNewIssues(t *testing.T) {
	NewIssues()
}

func TestIssuesEqual(t *testing.T) {
	expectIssuesEqual(t, Issues{
		Errors:   []string{},
		Warnings: []string{},
	}, NewIssues())

	expectIssuesEmpty(t, Issues{
		Errors:   []string{},
		Warnings: []string{},
	})

	expectIssuesEqual(t, Issues{
		Errors:   []string{"Single Error"},
		Warnings: []string{},
	}, NewIssues().addError("Single Error"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{},
	}, NewIssues().addError("First Error").addError("Second Error"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addWarning("Single Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarning("First Warning").addWarning("Second Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"Single Error"},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addError("Single Error").addWarning("Single Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarning("First Warning").addError("First Error").addWarning("Second Warning").addError("Second Error"))
}

func TestIssuesNotEqual(t *testing.T) {
	expectIssuesNotEqual(t,
		NewIssues().addWarning("test"),
		NewIssues().addError("test"),
	)

	expectIssuesNotEqual(t,
		NewIssues().addError("first").addError("second"),
		NewIssues().addError("first"),
	)

	expectIssuesNotEqual(t,
		NewIssues().addError("pie").addError("cake").addError("anything you bake"),
		NewIssues().addError("cake").addError("pie").addError("anything you bake"),
	)
}
