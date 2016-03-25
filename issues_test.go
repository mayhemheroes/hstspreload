package hstspreload

import (
	"runtime"
	"strings"
	"testing"
)

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
	if !AreIssuesEqual(expected, actual) {
		t.Errorf(`Issues should be equal. (%s:%d)

## Expected

%v

## Actual

%v

`, file, line, expected, actual)
	}
}

func expectIssuesNotEqual(t *testing.T, actual Issues, expected Issues) {
	file, line := getCaller(1)
	if AreIssuesEqual(expected, actual) {
		t.Errorf(`Issues should not be equal. (%s:%d)

## (Not) Expected

%v

## Actual

%v

`, file, line, expected, actual)
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
		errors:   []string{},
		warnings: []string{},
	}, NewIssues())

	expectIssuesEmpty(t, Issues{
		errors:   []string{},
		warnings: []string{},
	})

	expectIssuesEqual(t, Issues{
		errors:   []string{"Single Error"},
		warnings: []string{},
	}, NewIssues().AddError("Single Error"))

	expectIssuesEqual(t, Issues{
		errors:   []string{"First Error", "Second Error"},
		warnings: []string{},
	}, NewIssues().AddError("First Error").AddError("Second Error"))

	expectIssuesEqual(t, Issues{
		errors:   []string{},
		warnings: []string{"Single Warning"},
	}, NewIssues().AddWarning("Single Warning"))

	expectIssuesEqual(t, Issues{
		errors:   []string{},
		warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().AddWarning("First Warning").AddWarning("Second Warning"))

	expectIssuesEqual(t, Issues{
		errors:   []string{"Single Error"},
		warnings: []string{"Single Warning"},
	}, NewIssues().AddError("Single Error").AddWarning("Single Warning"))

	expectIssuesEqual(t, Issues{
		errors:   []string{"First Error", "Second Error"},
		warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().AddWarning("First Warning").AddError("First Error").AddWarning("Second Warning").AddError("Second Error"))
}

func TestIssuesNotEqual(t *testing.T) {
	expectIssuesNotEqual(t,
		NewIssues().AddWarning("test"),
		NewIssues().AddError("test"),
	)

	expectIssuesNotEqual(t,
		NewIssues().AddError("first").AddError("second"),
		NewIssues().AddError("first"),
	)

	expectIssuesNotEqual(t,
		NewIssues().AddError("pie").AddError("cake").AddError("anything you bake"),
		NewIssues().AddError("cake").AddError("pie").AddError("anything you bake"),
	)
}
