package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/floating-cat/heteroglossia/util/errors"
)

func needUpdateFile(filepath string, needUpdateInterval time.Duration) (bool, error) {
	ruleFileInfo, err := os.Stat(filepath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	interval := time.Now().Sub(ruleFileInfo.ModTime())
	return interval >= needUpdateInterval, nil
}

func updateFile(client *http.Client, filePath, fileURL, fileSHA256SumURL string) error {
	files := make([]*os.File, 0, 2)
	urls := []string{fileURL, fileSHA256SumURL}
	for _, url := range urls {
		file, err := downloadFile(client, url)
		if err != nil {
			return err
		}
		//goland:noinspection GoDeferInLoop
		defer func(file *os.File) {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}(file)
		files = append(files, file)
	}

	for _, file := range files {
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	filename := path.Base(fileURL)
	err := verifyRulesFileSHA256Sum(files[0], files[1], filename)
	if err != nil {
		return err
	}

	_, err = files[0].Seek(0, io.SeekStart)
	if err != nil {
		return errors.WithStack(err)
	}
	srcFile := files[0]
	if strings.HasSuffix(filename, ".tar.gz") {
		newDownloadHgBinaryPath, err := extractHgBinaryTarGz(files[0])
		if err != nil {
			return err
		}
		newDownloadHgBinaryFile, err := os.Open(newDownloadHgBinaryPath)
		if err != nil {
			_ = os.Remove(newDownloadHgBinaryPath)
			return errors.WithStack(err)
		}
		defer func() {
			_ = newDownloadHgBinaryFile.Close()
			_ = os.Remove(newDownloadHgBinaryFile.Name())
		}()
		srcFile = newDownloadHgBinaryFile
	}

	err = replaceFile(srcFile, filePath)
	if err != nil {
		return err
	}
	return nil
}

func downloadFile(client *http.Client, url string) (_ *os.File, err error) {
	filename := path.Base(url)
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// On error the caller never receives the file, so close and remove it here to
	// avoid leaking the temp file. On success the caller owns it.
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()

	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Newf("bad status %v when downloading the %v file", resp.Status, filename)
	}

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return file, nil
}

func verifyRulesFileSHA256Sum(file *os.File, sha256SumFile *os.File, filename string) error {
	hash := sha256.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = io.Copy(hash, file)
	if err != nil {
		return errors.WithStack(err)
	}
	downloadFileSum := hex.EncodeToString(hash.Sum(nil))

	scanner := bufio.NewScanner(sha256SumFile)
	regexStr := fmt.Sprintf("^([^\\s]+)%v%v$", "\\s+", regexp.QuoteMeta(filename))
	regex := regexp.MustCompile(regexStr)
	expectedSum := ""
	for scanner.Scan() {
		match := regex.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			expectedSum = match[1]
			break
		}
	}
	if expectedSum == "" {
		return errors.Newf("fail to find the SHA256 sum for the '%v' file", filename)
	}

	if downloadFileSum != expectedSum {
		return errors.Newf("the downloaded %v file's SHA256 is not the same as the one from the downloaded sha256sum file", file.Name())
	}
	return nil
}

// extractHgBinaryTarGz extracts only the hg binary from tarGzFile into a new
// temp file and returns its path. The caller owns the returned file.
func extractHgBinaryTarGz(tarGzFile *os.File) (string, error) {
	gzipReader, err := gzip.NewReader(tarGzFile)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func() {
		_ = gzipReader.Close()
	}()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.IsIoEof(err) {
			return "", errors.Newf("fail to find the %v binary in the downloaded compressed file %v",
				hgBinaryName, tarGzFile.Name())
		}
		if err != nil {
			return "", errors.WithStack(err)
		}
		if header.Typeflag == tar.TypeReg && path.Base(header.Name) == hgBinaryName {
			return extractToTempFile(tarReader, header.FileInfo().Mode().Perm())
		}
	}
}

func extractToTempFile(src io.Reader, perm os.FileMode) (_ string, err error) {
	file, err := os.CreateTemp("", hgBinaryName)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = errors.WithStack(closeErr)
		}
		if err != nil {
			_ = os.Remove(file.Name())
		}
	}()

	_, err = io.Copy(file, src)
	if err != nil {
		return "", errors.WithStack(err)
	}
	err = file.Chmod(perm)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return file.Name(), nil
}

func replaceFile(src *os.File, dstFilepath string) error {
	err := os.MkdirAll(filepath.Dir(dstFilepath), 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	dstNewFilepath, err := os.Create(dstFilepath + ".new")
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		_ = dstNewFilepath.Close()
	}()
	_, err = io.Copy(dstNewFilepath, src)
	if err != nil {
		return errors.WithStack(err)
	}
	srcFileStat, err := src.Stat()
	if err != nil {
		return errors.WithStack(err)
	}
	err = os.Chmod(dstNewFilepath.Name(), srcFileStat.Mode())
	if err != nil {
		return errors.WithStack(err)
	}

	if runtime.GOOS == "windows" {
		err = os.Rename(dstFilepath, dstFilepath+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.WithStack(err)
		}
	}
	return errors.WithStack(os.Rename(dstFilepath+".new", dstFilepath))
}
