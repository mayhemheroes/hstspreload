package hstspreload

import (
	"runtime"
	"testing"
	"strings"
)

func TestNewIssues(t *testing.T) {
	NewIssues()
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

func expectIssuesEqualImpl(t *testing.T, testCase string, actual Issues, expected Issues, levelsUp int) {
	file, line := getCaller(levelsUp + 1)
	if !AreIssuesEqual(expected, actual) {
		t.Errorf(`%s

Issues should be equal.
(%s:%d)

## Expected

%v

## Actual

%v

`, testCase, file, line, expected, actual)
	}
}

func expectIssuesEqual(t *testing.T, testCase string, actual Issues, expected Issues) {
	expectIssuesEqualImpl(t, testCase, actual, expected, 1)
}

// This function name is more clear than comparing whether we're "equal" to empty.
func expectIssuesEmpty(t *testing.T, testCase string, actual Issues) {
	expectIssuesEqualImpl(t, testCase, actual, NewIssues(), 1)
}

func expectIssuesNotEqual(t *testing.T, testCase string, actual Issues, expected Issues) {
	file, line := getCaller(1)
	if AreIssuesEqual(expected, actual) {
		t.Errorf(`%s

Issues should not be equal.
(%s:%d)

## Expected

%v

## Actual

%v

`, testCase, file, line, expected, actual)
	}
}

func TestIssuesEqual(t *testing.T) {
	expectIssuesEqual(t, "Issues: blank", Issues{
		errors:   []string{},
		warnings: []string{},
	}, NewIssues())

	expectIssuesEmpty(t, "Issues: blank", Issues{
		errors:   []string{},
		warnings: []string{},
	})

	expectIssuesEqual(t, "Issues: single error", Issues{
		errors:   []string{"Single Error"},
		warnings: []string{},
	}, NewIssues().AddError("Single Error"))

	expectIssuesEqual(t, "Issues: multiple errors", Issues{
		errors:   []string{"First Error", "Second Error"},
		warnings: []string{},
	}, NewIssues().AddError("First Error").AddError("Second Error"))

	expectIssuesEqual(t, "Issues: single warning", Issues{
		errors:   []string{},
		warnings: []string{"Single Warning"},
	}, NewIssues().AddWarning("Single Warning"))

	expectIssuesEqual(t, "Issues: multiple warnings", Issues{
		errors:   []string{},
		warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().AddWarning("First Warning").AddWarning("Second Warning"))

	expectIssuesEqual(t, "Issues: single error, single warning", Issues{
		errors:   []string{"Single Error"},
		warnings: []string{"Single Warning"},
	}, NewIssues().AddError("Single Error").AddWarning("Single Warning"))

	expectIssuesEqual(t, "Issues: multiple errors and warnings", Issues{
		errors:   []string{"First Error", "Second Error"},
		warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().AddWarning("First Warning").AddError("First Error").AddWarning("Second Warning").AddError("Second Error"))
}

func TestIssuesNotEqual(t *testing.T) {
	expectIssuesNotEqual(t, "Issues: warning vs. error",
		NewIssues().AddWarning("test"),
		NewIssues().AddError("test"),
	)

	expectIssuesNotEqual(t, "Issues: extra error",
		NewIssues().AddError("first").AddError("second"),
		NewIssues().AddError("first"),
	)

	expectIssuesNotEqual(t, "Issues: ordering",
		NewIssues().AddError("pie").AddError("cake").AddError("anything you bake"),
		NewIssues().AddError("cake").AddError("pie").AddError("anything you bake"),
	)

	// TODO: add more cases
}
