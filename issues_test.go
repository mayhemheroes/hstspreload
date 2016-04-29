package hstspreload

import "testing"

const (
	issuesShouldMatch = `Issues should match expected.
## Actual

%#v

## Expected

%#v

`
	issuesShouldBeEmpty = `Issues should be empty.
## Actual

%#v

`
)

// issuesMatchExpected checks that the `actual` issues match the
// `expected` ones. This function always checks that both the lists of
// Errors and Warnings have the same number of `Issue`s with the same
// `IssuesCode`s codes in the same order. If any issues in `expected`
// have the Summary or Message field set, the field is also compared
// against the field from the corresponding issue in `actual`.
func issuesMatchExpected(actual, expected Issues) bool {
	if len(actual.Errors) != len(expected.Errors) {
		return false
	}

	if len(actual.Warnings) != len(expected.Warnings) {
		return false
	}

	for e := range actual.Errors {
		if actual.Errors[e].Code != expected.Errors[e].Code {
			return false
		}
		if expected.Errors[e].Summary != "" && actual.Errors[e].Summary != expected.Errors[e].Summary {
			return false
		}
		if expected.Errors[e].Message != "" && actual.Errors[e].Message != expected.Errors[e].Message {
			return false
		}
	}

	for w := range actual.Warnings {
		if actual.Warnings[w].Code != expected.Warnings[w].Code {
			return false
		}
		if expected.Warnings[w].Summary != "" && actual.Warnings[w].Summary != expected.Warnings[w].Summary {
			return false
		}
		if expected.Warnings[w].Message != "" && actual.Warnings[w].Message != expected.Warnings[w].Message {
			return false
		}
	}

	return true
}

func issuesEmpty(iss Issues) bool {
	return issuesMatchExpected(iss, Issues{})
}

var issuesMatchExpectedTests = []struct {
	actual   Issues
	expected Issues
}{
	{Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}, Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}},
	{Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}, Issues{}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{Issue{
				Code:    "error1",
				Summary: "Summary 1",
				Message: "Single Error",
			}},
		}},
	{Issues{}.addErrorf("error1", "", ""),
		Issues{
			Errors: []Issue{Issue{
				Code: "error1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{Issue{
				Code:    "error1",
				Summary: "Summary 1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error"),
		Issues{
			Errors: []Issue{Issue{
				Code: "error1",
			}},
		}},
	{Issues{}.addErrorf("error1", "", "Single Error").addErrorf("error2", "", "Second Error"),
		Issues{
			Errors: []Issue{
				Issue{Code: "error1"},
				Issue{Code: "error2", Message: "Second Error"},
			},
		}},
	{Issues{}.addWarningf("warning1", "Summary 1", "Single warning"),
		Issues{
			Warnings: []Issue{Issue{
				Code: "warning1",
			}},
		}},
	{Issues{}.addErrorf("error1", "Summary 1", "Single Error").addWarningf("warning1", "Summary 1", "Single warning"),
		Issues{
			Errors: []Issue{Issue{
				Code: "error1",
			}},
			Warnings: []Issue{Issue{
				Code: "warning1",
			}},
		}},
}

func TestIssuesMatchExpected(t *testing.T) {
	for _, tt := range issuesMatchExpectedTests {
		if !issuesMatchExpected(tt.actual, tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

var issuesNotEqualTests = []struct {
	actual   Issues
	expected Issues
}{
	{
		Issues{Errors: []Issue{Issue{Code: "test1"}}},
		Issues{Warnings: []Issue{Issue{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{Issue{Code: "test1"}, Issue{Code: "test2"}}},
		Issues{Errors: []Issue{Issue{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{Issue{Code: "pie"}, Issue{Code: "cake"}, Issue{Code: "anything you bake"}}},
		Issues{Errors: []Issue{Issue{Code: "cake"}, Issue{Code: "pie"}, Issue{Code: "anything you bake"}}},
	},
}

func TestIssuesNotEqual(t *testing.T) {
	for _, tt := range issuesNotEqualTests {
		if issuesMatchExpected(tt.actual, tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

func TestAddUniqueErrorf(t *testing.T) {
	iss := Issues{
		Errors: []Issue{
			Issue{Code: "error1"},
			Issue{Code: "error2"},
		},
	}

	var expected Issues

	iss = iss.addUniqueErrorf("error2", "", "")
	expected = Issues{
		Errors: []Issue{
			Issue{Code: "error1"},
			Issue{Code: "error2"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueErrorf("error3", "", "")
	expected = Issues{
		Errors: []Issue{
			Issue{Code: "error1"},
			Issue{Code: "error2"},
			Issue{Code: "error3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueErrorf("error1", "", "")
	expected = Issues{
		Errors: []Issue{
			Issue{Code: "error1"},
			Issue{Code: "error2"},
			Issue{Code: "error3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}

func TestAddUniqueWarningf(t *testing.T) {
	iss := Issues{
		Warnings: []Issue{
			Issue{Code: "warning1"},
			Issue{Code: "warning2"},
		},
	}

	var expected Issues

	iss = iss.addUniqueWarningf("warning2", "", "")
	expected = Issues{
		Warnings: []Issue{
			Issue{Code: "warning1"},
			Issue{Code: "warning2"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueWarningf("warning3", "", "")
	expected = Issues{
		Warnings: []Issue{
			Issue{Code: "warning1"},
			Issue{Code: "warning2"},
			Issue{Code: "warning3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss = iss.addUniqueWarningf("warning1", "", "")
	expected = Issues{
		Warnings: []Issue{
			Issue{Code: "warning1"},
			Issue{Code: "warning2"},
			Issue{Code: "warning3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}
