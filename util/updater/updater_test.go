package updater

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

func TestExtractHgBinaryTarGz(t *testing.T) {
	binaryContent := "hg stub binary"
	tarGzFile := newTarGzFile(t, map[string]string{
		"LICENSE":    "license",
		hgBinaryName: binaryContent,
	})

	binaryPath, err := extractHgBinaryTarGz(tarGzFile)
	must.NoError(t, err)
	defer func() {
		_ = os.Remove(binaryPath)
	}()

	content, err := os.ReadFile(binaryPath)
	must.NoError(t, err)
	must.Eq(t, binaryContent, string(content))
}

func newTarGzFile(t *testing.T, files map[string]string) *os.File {
	file, err := os.Create(filepath.Join(t.TempDir(), "hg.tar.gz"))
	must.NoError(t, err)
	t.Cleanup(func() {
		_ = file.Close()
	})

	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		err = tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0600,
			Size:     int64(len(content)),
		})
		must.NoError(t, err)
		_, err = tarWriter.Write([]byte(content))
		must.NoError(t, err)
	}
	must.NoError(t, tarWriter.Close())
	must.NoError(t, gzipWriter.Close())

	_, err = file.Seek(0, 0)
	must.NoError(t, err)
	return file
}
