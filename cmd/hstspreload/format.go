package main

import "fmt"

const (
	reset  = "\033[0m"
	red    = "\033[0;31m"
	yellow = "\033[0;33m"
	green  = "\033[0;32m"
	bold   = "\033[1m"
)

const (
	underline      = "\033[4m"
	resetUnderline = "\033[0m"
)

func format(str string) {
	fmt.Printf(str)
}
