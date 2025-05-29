package testhelpers

import (
	"bytes"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

// func CaptureOutput(f func()) string {
// 	var buf bytes.Buffer
// 	logrus.SetOutput(&buf)
// 	defer logrus.SetOutput(os.Stderr)

// 	f()
// 	return buf.String()
// }

func CaptureOutput(f func()) string {
	oldOut := os.Stdout
	oldErr := os.Stderr

	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	logrus.SetOutput(w)
	defer logrus.SetOutput(os.Stderr)

	f()

	w.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}
