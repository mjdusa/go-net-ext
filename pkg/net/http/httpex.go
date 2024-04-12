package httpex

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"time"

	"github.com/mjdusa/go-ext/pkg/fileex"
)

func WrapError(message string, err error) error {
	return fmt.Errorf("%s: %w", message, err)
}

// HTTPGet - HTTP Get from URL.
func HTTPGet(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
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

// HTTPGetFile - HTTP Get from URL.
func HTTPGetFile(ctx context.Context, url string, timeout time.Duration, fqfn string, perm fs.FileMode) error {
	data, err := HTTPGet(ctx, url, timeout)
	if err != nil {
		return WrapError("HttpGet() error", err)
	}

	err = fileex.WriteAllFile(fqfn, data, perm)
	if err != nil {
		return WrapError("WriteAllFile() error", err)
	}

	return nil
}
