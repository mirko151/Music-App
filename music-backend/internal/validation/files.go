package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
)

const (
	DefaultMaxUploadBytes int64 = 25 << 20 // 25MB
)

// AllowedAudioMIMEs je whitelist MIME tipova za audio fajlove.
var AllowedAudioMIMEs = map[string]bool{
	"audio/mpeg":     true, // mp3
	"audio/wav":      true,
	"audio/x-wav":    true,
	"audio/flac":     true,
	"audio/aac":      true,
	"audio/mp4":      true, // m4a u nekim browserima
	"application/ogg": true,
}

// AllowedAudioExtensions je whitelist ekstenzija.
var AllowedAudioExtensions = map[string]bool{
	".mp3": true,
	".wav": true,
	".flac": true,
	".aac": true,
	".m4a": true,
	".ogg": true,
}

// ValidateUploadedFile radi:
// - provera privilegija ide pre poziva (2.17)
// - provera tipa datoteke (whitelisting)
// - boundary check (max bytes)
// - izračunavanje SHA256 (integritet)
func ValidateUploadedFile(fileHeader *multipart.FileHeader, maxBytes int64) (mimeType string, sha256Hex string, err error) {
	if fileHeader == nil {
		return "", "", errors.New("missing file")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxUploadBytes
	}
	if fileHeader.Size <= 0 {
		return "", "", errors.New("empty file")
	}
	if fileHeader.Size > maxBytes {
		return "", "", errors.New("file too large")
	}

	name := fileHeader.Filename
	ext := strings.ToLower(filepath.Ext(name))
	if !AllowedAudioExtensions[ext] {
		return "", "", errors.New("file extension not allowed")
	}

	f, err := fileHeader.Open()
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	limited := io.LimitReader(f, maxBytes)
	buf := make([]byte, 512)
	n, _ := io.ReadFull(limited, buf)
	buf = buf[:n]
	mimeType = http.DetectContentType(buf)
	if !AllowedAudioMIMEs[mimeType] {
		return "", "", errors.New("file MIME type not allowed")
	}

	h := sha256.New()
	_, _ = h.Write(buf)
	if _, err := io.Copy(h, limited); err != nil {
		return "", "", err
	}
	sha256Hex = hex.EncodeToString(h.Sum(nil))
	return mimeType, sha256Hex, nil
}
