package updater

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floating-cat/heteroglossia/util/errors"
)

func needUpdateFile(filePath string, needUpdateInterval time.Duration) (bool, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, errors.WithStack(err)
	}
	return time.Since(fileInfo.ModTime()) >= needUpdateInterval, nil
}

func updateFile(client *http.Client, filePath, fileURL, fileSHA256SumURL string) error {
	filename := path.Base(fileURL)
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()

	hash := sha256.New()
	err = download(client, fileURL, io.MultiWriter(file, hash))
	if err != nil {
		return err
	}
	var sha256Sums bytes.Buffer
	err = download(client, fileSHA256SumURL, &sha256Sums)
	if err != nil {
		return err
	}
	err = verifySHA256Sum(hash.Sum(nil), &sha256Sums, filename)
	if err != nil {
		return err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return errors.WithStack(err)
	}
	if strings.HasSuffix(filename, ".tar.gz") {
		return extractHgBinaryTarGz(file, filePath)
	}
	return replaceFile(file, 0644, filePath)
}

func download(client *http.Client, url string, dst io.Writer) error {
	resp, err := client.Get(url)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.Newf("bad status %v when downloading the %v file", resp.Status, path.Base(url))
	}

	_, err = io.Copy(dst, resp.Body)
	return errors.WithStack(err)
}

func verifySHA256Sum(sum []byte, sha256Sums io.Reader, filename string) error {
	scanner := bufio.NewScanner(sha256Sums)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[1] == filename {
			if fields[0] != hex.EncodeToString(sum) {
				return errors.Newf("the downloaded %v file's SHA256 "+
					"is not the same as the one from the downloaded sha256sum file", filename)
			}
			return nil
		}
	}
	return errors.Newf("fail to find the SHA256 sum for the '%v' file", filename)
}

// extractHgBinaryTarGz extracts only the hg binary from tarGzFile and replaces
// dstFilepath with it.
func extractHgBinaryTarGz(tarGzFile *os.File, dstFilepath string) error {
	gzipReader, err := gzip.NewReader(tarGzFile)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		_ = gzipReader.Close()
	}()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.IsIoEof(err) {
			return errors.Newf("fail to find the %v binary in the downloaded compressed file %v",
				hgBinaryName, tarGzFile.Name())
		}
		if err != nil {
			return errors.WithStack(err)
		}
		if header.Typeflag == tar.TypeReg && path.Base(header.Name) == hgBinaryName {
			return replaceFile(tarReader, header.FileInfo().Mode().Perm(), dstFilepath)
		}
	}
}

// replaceFile replaces dstFilepath with the content of src. The new file keeps
// the permissions of the file it replaces, or uses perm if there's none.
func replaceFile(src io.Reader, perm os.FileMode, dstFilepath string) error {
	err := os.MkdirAll(filepath.Dir(dstFilepath), 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	fileInfo, err := os.Stat(dstFilepath)
	if err == nil {
		perm = fileInfo.Mode().Perm()
	}
	newFilepath := dstFilepath + ".new"
	err = writeFile(newFilepath, src, perm)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// Windows can't overwrite a running executable, but it can rename it.
		err = os.Rename(dstFilepath, dstFilepath+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.WithStack(err)
		}
	}
	return errors.WithStack(os.Rename(newFilepath, dstFilepath))
}

// writeFile closes the file before returning, since Windows can't rename a file
// that is still open.
func writeFile(filePath string, src io.Reader, perm os.FileMode) (err error) {
	file, err := os.Create(filePath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = errors.WithStack(closeErr)
		}
	}()

	_, err = io.Copy(file, src)
	if err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(file.Chmod(perm))
}
