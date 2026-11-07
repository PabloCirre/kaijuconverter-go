package kaijuconverter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectMagicBytes(t *testing.T) {
	testCases := []struct {
		name        string
		header      []byte
		expectedExt string
		expectedMIM string
	}{
		{"PDF", []byte("%PDF-1.7 header stream"), "pdf", "application/pdf"},
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00}, "png", "image/png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, "jpeg", "image/jpeg"},
		{"GIF87a", []byte("GIF87a\x01\x00"), "gif", "image/gif"},
		{"GIF89a", []byte("GIF89a\x01\x00"), "gif", "image/gif"},
		{"WEBP", []byte("RIFF\x20\x00\x00\x00WEBPVP8 "), "webp", "image/webp"},
		{"AVIF", []byte("\x00\x00\x00\x1cftypavif\x00\x00\x00\x00mif1"), "avif", "image/avif"},
		{"HEIC", []byte("\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1"), "heic", "image/heic"},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00}, "zip", "application/zip"},
		{"7Z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z", "application/x-7z-compressed"},
		{"RAR4", []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "rar", "application/vnd.rar"},
		{"RAR5", []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "rar", "application/vnd.rar"},
		{"GZ", []byte{0x1F, 0x8B, 0x08, 0x00}, "gz", "application/gzip"},
		{"BZ2", []byte{0x42, 0x5A, 0x68, 0x39}, "bz2", "application/x-bzip2"},
		{"XZ", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "xz", "application/x-xz"},
		{"ZSTD", []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00}, "zst", "application/zstd"},
		{"MP3 ID3", []byte("ID3\x04\x00\x00"), "mp3", "audio/mpeg"},
		{"FLAC", []byte("fLaC\x00\x00\x00\x22"), "flac", "audio/flac"},
		{"WAV", []byte("RIFF\x24\x08\x00\x00WAVEfmt "), "wav", "audio/wav"},
		{"OGG", []byte("OggS\x00\x02\x00"), "ogg", "audio/ogg"},
		{"MP4", []byte("\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"), "mp4", "video/mp4"},
		{"MKV", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81}, "mkv", "video/x-matroska"},
		{"AVI", []byte("RIFF\x40\x00\x00\x00AVI LIST"), "avi", "video/x-msvideo"},
		{"WASM", []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}, "wasm", "application/wasm"},
		{"ELF", []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00}, "elf", "application/x-elf"},
		{"SQLITE", []byte("SQLite format 3\x00\x10\x00"), "sqlite", "application/vnd.sqlite3"},
		{"PARQUET", []byte("PAR1\x15\x00"), "parquet", "application/vnd.apache.parquet"},
		{"STL ASCII", []byte("solid cube_model\n  facet normal 0 0 0"), "stl", "model/stl"},
		{"TTF", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x0B}, "ttf", "font/ttf"},
		{"WOFF2", []byte("wOF2\x00\x01\x00\x00"), "woff2", "font/woff2"},
		{"WOFF", []byte("wOFF\x00\x01\x00\x00"), "woff", "font/woff"},
		{"BMP", []byte("BM\x36\x00\x0C\x00"), "bmp", "image/bmp"},
		{"TIFF Little Endian", []byte{0x49, 0x49, 0x2A, 0x00, 0x08, 0x00}, "tiff", "image/tiff"},
		{"TIFF Big Endian", []byte{0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x08}, "tiff", "image/tiff"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := DetectMagicBytes(tc.header)
			if !ok {
				t.Fatalf("expected detection for %s, got false", tc.name)
			}
			if info.Extension != tc.expectedExt {
				t.Errorf("expected ext %s, got %s", tc.expectedExt, info.Extension)
			}
			if info.MIMEType != tc.expectedMIM {
				t.Errorf("expected MIME %s, got %s", tc.expectedMIM, info.MIMEType)
			}
			if info.DocURL == "" {
				t.Errorf("expected non-empty DocURL for %s", tc.name)
			}
		})
	}

	// Unknown signature test
	_, ok := DetectMagicBytes([]byte{0x00, 0x00, 0x00, 0x00})
	if ok {
		t.Errorf("expected false for unknown bytes, got true")
	}
}

func TestClientConfig(t *testing.T) {
	client := NewClient(
		WithBaseURL("https://example.com/api"),
		WithAPIKey("test-secret-key"),
	)
	if client.BaseURL != "https://example.com/api" {
		t.Errorf("expected custom base url, got %s", client.BaseURL)
	}
	if client.APIKey != "test-secret-key" {
		t.Errorf("expected custom api key, got %s", client.APIKey)
	}
}

func TestClientCallMCP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != APIEndpointMCP {
			t.Errorf("expected path %s, got %s", APIEndpointMCP, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"result":{"converted":true,"format":"avif","bytes":12480}}`))
	}))
	defer ts.Close()

	client := NewClient(WithBaseURL(ts.URL))
	res, err := client.CallMCP(context.Background(), "convert_image", map[string]interface{}{
		"target": "avif",
		"quality": 85,
	})
	if err != nil {
		t.Fatalf("CallMCP failed: %v", err)
	}
	if res["converted"] != true || res["format"] != "avif" {
		t.Errorf("unexpected MCP result: %v", res)
	}
}
