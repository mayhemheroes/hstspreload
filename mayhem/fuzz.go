package fuzz

import "github.com/chromium/hstspreload"

func mayhemit(bytes []byte) int {

    content := string(bytes)
    hstspreload.ParseHeaderString(content)
    return 0
}

func Fuzz(data []byte) int {
    _ = mayhemit(data)
    return 0
}