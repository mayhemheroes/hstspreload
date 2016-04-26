package hstspreload

import "testing"

const (
	issuesShouldBeEqual = `Issues should be equal.
## Actual

%#v

## (Not) Expected

%#v

`
	issuesShouldBeEmpty = `Issues should be empty.
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
