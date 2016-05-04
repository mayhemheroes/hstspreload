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
func issuesMatchExpected(actual, expected *Issues) bool {
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

func issuesEmpty(iss *Issues) bool {
	return issuesMatchExpected(iss, &Issues{})
}

func TestIssuesMatchExpected(t *testing.T) {

	type testCase struct {
		actual   *Issues
		expected *Issues
	}
	issuesMatchExpectedTests := []testCase{}

	var actual *Issues
	var expected *Issues

	actual = &Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}
	expected = &Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{
		Errors:   []Issue{},
		Warnings: []Issue{},
	}
	expected = &Issues{}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addErrorf("error1", "Summary 1", "Single Error")
	expected = &Issues{
		Errors: []Issue{Issue{
			Code:    "error1",
			Summary: "Summary 1",
			Message: "Single Error",
		}},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addErrorf("error1", "Summary 1", "Single Error")
	expected = &Issues{
		Errors: []Issue{Issue{
			Code:    "error1",
			Summary: "Summary 1",
		}},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addErrorf("error1", "Summary 1", "Single Error")
	expected = &Issues{
		Errors: []Issue{Issue{
			Code: "error1",
		}},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addErrorf("error1", "", "First Error")
	actual.addErrorf("error2", "", "Second Error")
	expected = &Issues{
		Errors: []Issue{
			Issue{Code: "error1"},
			Issue{Code: "error2", Message: "Second Error"},
		},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addWarningf("warning1", "Summary 1", "Single warning")
	expected = &Issues{
		Warnings: []Issue{Issue{
			Code: "warning1",
		}},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

	actual = &Issues{}
	actual.addErrorf("error1", "Summary 1", "Single Error")
	actual.addWarningf("warning1", "Summary 1", "Single warning")
	expected = &Issues{
		Errors: []Issue{Issue{
			Code: "error1",
		}},
		Warnings: []Issue{Issue{
			Code: "warning1",
		}},
	}
	issuesMatchExpectedTests = append(issuesMatchExpectedTests, testCase{actual, expected})

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
		Issues{Errors: []Issue{{Code: "test1"}}},
		Issues{Warnings: []Issue{{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{{Code: "test1"}, {Code: "test2"}}},
		Issues{Errors: []Issue{{Code: "test1"}}},
	},
	{
		Issues{Errors: []Issue{{Code: "pie"}, {Code: "cake"}, {Code: "anything you bake"}}},
		Issues{Errors: []Issue{{Code: "cake"}, {Code: "pie"}, {Code: "anything you bake"}}},
	},
}

func TestIssuesNotEqual(t *testing.T) {
	for _, tt := range issuesNotEqualTests {
		if issuesMatchExpected(&tt.actual, &tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

func TestAddUniqueErrorf(t *testing.T) {
	iss := &Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
		},
	}

	var expected *Issues

	iss.addUniqueErrorf("error2", "", "")
	expected = &Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss.addUniqueErrorf("error3", "", "")
	expected = &Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
			{Code: "error3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss.addUniqueErrorf("error1", "", "")
	expected = &Issues{
		Errors: []Issue{
			{Code: "error1"},
			{Code: "error2"},
			{Code: "error3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}

func TestAddUniqueWarningf(t *testing.T) {
	iss := &Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
		},
	}

	var expected *Issues

	iss.addUniqueWarningf("warning2", "", "")
	expected = &Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss.addUniqueWarningf("warning3", "", "")
	expected = &Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
			{Code: "warning3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}

	iss.addUniqueWarningf("warning1", "", "")
	expected = &Issues{
		Warnings: []Issue{
			{Code: "warning1"},
			{Code: "warning2"},
			{Code: "warning3"},
		},
	}
	if !issuesMatchExpected(iss, expected) {
		t.Errorf(issuesShouldMatch, iss, expected)
	}
}
