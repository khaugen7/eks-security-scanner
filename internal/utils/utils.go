package utils

import (
	"fmt"
	"strings"
)

func PrintScannerHeader(name string) string {
	border := strings.Repeat("=", len(name)+8)
	return fmt.Sprintf("\n%s\n>>> %s <<<\n%s\n\n", border, name, border)
}
