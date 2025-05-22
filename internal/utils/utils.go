package utils

import (
	"fmt"
	"strings"
)

func PrintScannerHeader(name string) {
	border := strings.Repeat("=", len(name)+8)
	fmt.Printf("\n%s\n>>> %s <<<\n%s\n\n", border, name, border)
}
