package updater

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/floating-cat/heteroglossia/util/cli"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/log"
	"golang.org/x/mod/semver"
)

const (
	hgBinaryLatestVersionURL        = "https://api.github.com/repos/floating-cat/heteroglossia/releases/latest"
	hgBinaryURLTemplate             = "https://github.com/floating-cat/heteroglossia/releases/download/%v/heteroglossia_%v_%v_%v.tar.gz"
	hgBinaryURLSHA256SumURLTemplate = "https://github.com/floating-cat/heteroglossia/releases/download/%v/sha256sums.txt"
)

func UpdateHgBinary(client *http.Client) (bool, string, error) {
	currentVersion := cli.VersionWithVPrefix()
	if !semver.IsValid(currentVersion) {
		return false, "", errors.New("the current binary has an invalid semantic version, so skip the update")
	}
	latestTagVersion, err := latestTagVersion(client)
	if err != nil {
		return false, "", err
	}
	if !semver.IsValid(latestTagVersion) {
		return false, "", errors.New("the latest version from GitHub is an invalid semantic version so skipping update")
	}

	if semver.Compare(latestTagVersion, currentVersion) > 0 {
		log.Info("start to update to the latest release version of heteroglossia", "version", latestTagVersion)
		// an absolute path returns
		executablePath, err := os.Executable()
		if err != nil {
			return false, "", errors.WithStack(err)
		}
		err = updateFile(client, executablePath, hgBinaryURL(latestTagVersion), hgBinaryURLSHA256SumURL(latestTagVersion))
		if err != nil {
			return false, "", err
		}
		return true, latestTagVersion, nil
	}
	return false, "", err
}

func latestTagVersion(client *http.Client) (string, error) {
	resp, err := client.Get(hgBinaryLatestVersionURL)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", errors.Newf("bad status %v when checking the latest heteroglossia version", resp.Status)
	}

	var latest latest
	err = json.UnmarshalRead(resp.Body, &latest)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if latest.TagName == "" {
		return "", errors.New("fail to get the last tag name from GitHub")
	}
	return latest.TagName, nil
}

type latest struct {
	TagName string `json:"tag_name"`
}

func hgBinaryURL(version string) string {
	return fmt.Sprintf(hgBinaryURLTemplate, version, version[1:], runtime.GOOS, runtime.GOARCH)
}

func hgBinaryURLSHA256SumURL(version string) string {
	return fmt.Sprintf(hgBinaryURLSHA256SumURLTemplate, version)
}
