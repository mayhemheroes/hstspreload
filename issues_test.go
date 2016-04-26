package hstspreload

import (
	"runtime"
	"strings"
	"testing"
)

const (
	issuesShouldBeEqual = `Issues should be equal.
## Actual

%#v

## (Not) Expected

%#v

`
	issuesShouldBeEmpty = `Issues be empty.
## Actual

%#v

`
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

func issuesEmpty(iss Issues) bool {
	return issuesEqual(iss, Issues{})
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

var issuesEqualTests = []struct {
	actual   Issues
	expected Issues
}{
	{Issues{
		Errors:   []string{},
		Warnings: []string{},
	}, Issues{
		Errors:   []string{},
		Warnings: []string{},
	}},
	{Issues{
		Errors:   []string{},
		Warnings: []string{},
	}, NewIssues()},
	{Issues{
		Errors:   []string{"Single Error"},
		Warnings: []string{},
	}, NewIssues().addErrorf("Single Error")},
	{Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{},
	}, NewIssues().addErrorf("First Error").addErrorf("Second Error")},
	{Issues{
		Errors:   []string{},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addWarningf("Single Warning")},
	{Issues{
		Errors:   []string{},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarningf("First Warning").addWarningf("Second Warning")},
	{Issues{
		Errors:   []string{"Single Error"},
		Warnings: []string{"Single Warning"},
	}, NewIssues().addErrorf("Single Error").addWarningf("Single Warning")},
	{Issues{
		Errors:   []string{"First Error", "Second Error"},
		Warnings: []string{"First Warning", "Second Warning"},
	}, NewIssues().addWarningf("First Warning").addErrorf("First Error").addWarningf("Second Warning").addErrorf("Second Error")},
}

func TestIssuesEqual(t *testing.T) {
	for _, tt := range issuesEqualTests {
		if !issuesEqual(tt.actual, tt.expected) {
			t.Errorf(issuesShouldBeEqual, tt.actual, tt.expected)
		}
	}
}

var issuesNotEqualTests = []struct {
	actual   Issues
	expected Issues
}{
	{NewIssues().addWarningf("test"),
		NewIssues().addErrorf("test")},
	{NewIssues().addErrorf("first").addErrorf("second"),
		NewIssues().addErrorf("first")},
	{NewIssues().addErrorf("pie").addErrorf("cake").addErrorf("anything you bake"),
		NewIssues().addErrorf("cake").addErrorf("pie").addErrorf("anything you bake")},
}

func TestIssuesNotEqual(t *testing.T) {
	for _, tt := range issuesNotEqualTests {
		if issuesEqual(tt.actual, tt.expected) {
			t.Errorf(issuesShouldBeEqual, tt.actual, tt.expected)
		}
	}
}

func TestAddUniqueErrorf(t *testing.T) {
	iss := Issues{
		Errors: []string{"error 1", "error 2"},
	}

	var expected Issues

	iss.addUniqueErrorf("error 2")
	expected = Issues{Errors: []string{"error 1", "error 2"}}
	if !issuesEqual(iss, expected) {
		t.Errorf(issuesShouldBeEqual, iss, expected)
	}

	iss.addUniqueErrorf("error 1")
	expected = Issues{Errors: []string{"error 1", "error 2"}}
	if !issuesEqual(iss, expected) {
		t.Errorf(issuesShouldBeEqual, iss, expected)
	}
}

func TestAddUniqueWarningf(t *testing.T) {
	iss := Issues{
		Warnings: []string{"warning 1", "warning 2"},
	}

	var expected Issues

	iss.addUniqueWarningf("warning 2")
	expected = Issues{Warnings: []string{"warning 1", "warning 2"}}
	if !issuesEqual(iss, expected) {
		t.Errorf(issuesShouldBeEqual, iss, expected)
	}

	iss.addUniqueWarningf("warning 1")
	expected = Issues{Warnings: []string{"warning 1", "warning 2"}}
	if !issuesEqual(iss, expected) {
		t.Errorf(issuesShouldBeEqual, iss, expected)
	}
}
