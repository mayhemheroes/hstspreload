package hstspreload

import (
	"runtime"
	"strings"
	"testing"
)

// Includes ordering of errors and warnings.
func issuesEqual(i1, i2 Issues) bool {
	// reflect.DeepEqual distinguishes between nil slices and 0-length slices, but
	// we consider these to be the same (e.g. "no errors" == "0 errors"), so we
	// implement our own comparison.

	if len(i1.Errors) != len(i2.Errors) {
		return false
	}

	if len(i1.Warnings) != len(i2.Warnings) {
		return false
	}

	for e := range i1.Errors {
		if i1.Errors[e] != i2.Errors[e] {
			return false
		}
	}

	for w := range i1.Warnings {
		if i1.Warnings[w] != i2.Warnings[w] {
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

%#v

## Expected

%#v

`, file, line, actual, expected)
	}
}

func expectIssuesNotEqual(t *testing.T, actual Issues, expected Issues) {
	file, line := getCaller(1)
	if issuesEqual(actual, expected) {
		t.Errorf(`Issues should not be equal. (%s:%d)

## Actual

%#v

## (Not) Expected

%#v

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
	}, NewIssues().addErrorf("Single Error"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{},
	}, NewIssues().addErrorf("First Error").addErrorf("Second Error"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addWarningf("Single Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarningf("First Warning").addWarningf("Second Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"Single Error"},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addErrorf("Single Error").addWarningf("Single Warning"))

	expectIssuesEqual(t, Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarningf("First Warning").addErrorf("First Error").addWarningf("Second Warning").addErrorf("Second Error"))
}

func TestIssuesNotEqual(t *testing.T) {
	expectIssuesNotEqual(t,
		NewIssues().addWarningf("test"),
		NewIssues().addErrorf("test"),
	)

	expectIssuesNotEqual(t,
		NewIssues().addErrorf("first").addErrorf("second"),
		NewIssues().addErrorf("first"),
	)

	expectIssuesNotEqual(t,
		NewIssues().addErrorf("pie").addErrorf("cake").addErrorf("anything you bake"),
		NewIssues().addErrorf("cake").addErrorf("pie").addErrorf("anything you bake"),
	)
}
