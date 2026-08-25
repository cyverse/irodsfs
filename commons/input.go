package commons

import (
	"fmt"
	"syscall"

	"golang.org/x/term"
)

var (
	selectedAll bool = false
)

func Input(msg string) string {
	red := "\033[31m"
	reset := "\033[0m"

	fmt.Printf("%s%s: %s", red, msg, reset)

	userInput := ""
	fmt.Scanln(&userInput)

	return userInput
}

func InputPassword(msg string) string {
	red := "\033[31m"
	reset := "\033[0m"

	fmt.Printf("%s%s: %s", red, msg, reset)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")

	if err != nil {
		return ""
	}

	return string(bytePassword)
}
