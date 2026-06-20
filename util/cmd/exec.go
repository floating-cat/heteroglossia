package cmd

import (
	"os/exec"
	"strings"

	"github.com/floating-cat/heteroglossia/util/errors"
)

func Run(name string, arg ...string) (string, error) {
	cmd, outBuilder, errBuilder := exec.Command(name, arg...), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outBuilder
	cmd.Stderr = errBuilder
	err := cmd.Run()
	stdout := outBuilder.String()
	stderr := errBuilder.String()
	if err != nil {
		return "", errors.Newf("standard output '%v' and standard error '%v' when running the command '%v %v': %.0w",
			stdout, stderr, name, strings.Join(arg, " "), err)
	}
	if errBuilder.Len() > 0 {
		return "", errors.Newf("standard output '%v' and standard error '%v' when running the command '%v %v'",
			stdout, stderr, name, strings.Join(arg, " "))
	}
	return outBuilder.String(), nil
}

func RunWithStdoutErrResults(name string, arg ...string) (string, string, error) {
	cmd, outputBuilder, errorBuilder := exec.Command(name, arg...), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outputBuilder
	cmd.Stderr = errorBuilder
	err := cmd.Run()
	if err != nil {
		return "", "", errors.Newf("error '%v' when running command '%v %v': %.0w",
			errorBuilder.String(), name, strings.Join(arg, " "), err)
	}
	return outputBuilder.String(), errorBuilder.String(), nil
}

func RunWithInput(name string, input string) (string, error) {
	cmd, outputBuilder, errorBuilder := exec.Command(name), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outputBuilder
	cmd.Stderr = errorBuilder
	cmd.Stdin = strings.NewReader(input)
	err := cmd.Run()
	if err != nil {
		return "", errors.Newf("error '%v' when running command '%v' with '%v' input: %.0w",
			errorBuilder.String(), name, input, err)
	}
	if errorBuilder.Len() > 0 {
		return "", errors.Newf("error '%v' when running command '%v' with '%v' input", errorBuilder.String(),
			name, input)
	}
	return outputBuilder.String(), nil
}
