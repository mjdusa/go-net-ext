package httpex

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"time"

	"github.com/mjdusa/go-ex/pkg/fileex"
)

func WrapError(message string, err error) error {
	return fmt.Errorf("%s: %w", message, err)
}

// Get - HTTP Get from URL.
func Get(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	client := http.Client{
		Timeout: timeout,
	}

	req, nerr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if nerr != nil {
		return []byte{}, WrapError("http.NewRequestWithContext(http.MethodGet, url, nil) error", nerr)
	}

	resp, derr := client.Do(req)
	if derr != nil {
		return []byte{}, WrapError("client.Do(req) error", derr)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bytes, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			return []byte{}, WrapError("io.ReadAll() error", rerr)
		}
		return bytes, nil
	}

	return []byte{}, fmt.Errorf("HTTP Status Code: %d returned", resp.StatusCode)
}

// GetFile - HTTP Get from URL.
func GetFile(ctx context.Context, url string, timeout time.Duration, fqfn string, perm fs.FileMode) error {
	data, err := Get(ctx, url, timeout)
	if err != nil {
		return WrapError("http.Get() error", err)
	}

	err = fileex.WriteAllFile(fqfn, data, perm)
	if err != nil {
		return WrapError("WriteAllFile() error", err)
	}

	return nil
}
