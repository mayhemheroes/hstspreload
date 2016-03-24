package hstspreload

type Issues struct {
  warnings []string
  errors []string
}

func (issues Issues) AddWarning(warning string) {
  issues.errors = append(issues.errors, warning)
}

func (issues Issues) AddError(err string) {
  issues.errors = append(issues.errors, err)
}

func (issues Issues) HasError() bool {
  return len(issues.errors) > 0
}

func (issuesTo Issues) CombineWith(issuesFrom Issues) {
  issuesTo.errors = append(issuesTo.errors, issuesFrom.errors...)
  issuesTo.warnings = append(issuesTo.warnings, issuesFrom.warnings...)
}