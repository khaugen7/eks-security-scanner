package scanner

import (
	"os"
	"testing"

	"github.com/khaugen7/eks-security-scanner/internal/logger"
)

func TestMain(m *testing.M) {
	logger.Init(false)
	code := m.Run()
	os.Exit(code)
}
