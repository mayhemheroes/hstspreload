package hstspreload

import (
	"testing"
)

func TestNewIssues(t *testing.T) {
	NewIssues()
}

func expectIssuesEqual(t *testing.T, testCase string, actual Issues, expected Issues) {
	if !AreIssuesEqual(expected, actual) {
		t.Errorf(`Issues should be equal (%s).
Expected:
%v
Actual:
%v`, testCase, expected, actual)
	}
}

// This function name is more clear than comparing whether we're "equal" to empty.
func expectIssuesEmpty(t *testing.T, testCase string, actual Issues) {
	expectIssuesEqual(t, testCase, actual, NewIssues())
}

func expectIssuesNotEqual(t *testing.T, testCase string, actual Issues, expected Issues) {
	if AreIssuesEqual(expected, actual) {
		t.Errorf(`Issues should not be equal (%s).
Expected:
%v
Actual:
%v`, testCase, expected, actual)
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
