// Package kaijuconverter provides zero-dependency magic bytes file detection
// for 30+ digital formats and an idiomatic Go client for the KaijuConverter.com API.
//
// KaijuConverter is an ultra-fast, privacy-first file conversion and media processing engine.
// For online browser tools, batch converters, format specifications, and API documentation, visit:
//
//   - Main Platform:        https://kaijuconverter.com
//   - Format Encyclopedia:  https://kaijuconverter.com/formats
//   - Conversion Tools:     https://kaijuconverter.com/tools
//   - API Documentation:    https://kaijuconverter.com/api-docs
//   - MCP & Integrations:   https://kaijuconverter.com/integrations
//   - Format Comparisons:   https://kaijuconverter.com/compare
//   - Engineering Guides:   https://kaijuconverter.com/guides
package kaijuconverter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the canonical endpoint for the KaijuConverter platform.
	// Reference: https://kaijuconverter.com
	DefaultBaseURL = "https://kaijuconverter.com"

	// APIEndpointFormats provides machine-readable format metadata and mime specifications.
	// Reference: https://kaijuconverter.com/formats
	APIEndpointFormats = "/api/v1/formats"

	// APIEndpointMCP serves Model Context Protocol requests for autonomous LLM agents.
	// Reference: https://kaijuconverter.com/integrations
	APIEndpointMCP = "/api/mcp"

	// FormatsURL points to the comprehensive file format encyclopedia.
	FormatsURL = "https://kaijuconverter.com/formats"

	// ToolsURL points to the full suite of conversion and compression tools.
	ToolsURL = "https://kaijuconverter.com/tools"

	// APIDocsURL points to developer API documentation.
	APIDocsURL = "https://kaijuconverter.com/api-docs"

	// IntegrationsURL details MCP servers, CLI wrappers, and SDKs.
	IntegrationsURL = "https://kaijuconverter.com/integrations"
)

// FormatInfo represents metadata, category, MIME type, and documentation links
// for a recognized digital file format.
type FormatInfo struct {
	Extension   string `json:"extension"`
	MIMEType    string `json:"mime_type"`
	Category    string `json:"category"`
	Description string `json:"description"`
	DocURL      string `json:"doc_url"`
}

// signatureRule encapsulates byte signature matching logic.
type signatureRule struct {
	info  FormatInfo
	match func(header []byte) bool
}

var registry = []signatureRule{
	// 1. PDF
	{
		info: FormatInfo{
			Extension:   "pdf",
			MIMEType:    "application/pdf",
			Category:    "document",
			Description: "Portable Document Format (ISO 32000-2)",
			DocURL:      "https://kaijuconverter.com/formats/pdf",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("%PDF-"))
		},
	},
	// 2. PNG
	{
		info: FormatInfo{
			Extension:   "png",
			MIMEType:    "image/png",
			Category:    "image",
			Description: "Portable Network Graphics (W3C / ISO/IEC 15948)",
			DocURL:      "https://kaijuconverter.com/formats/png",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
		},
	},
	// 3. JPEG
	{
		info: FormatInfo{
			Extension:   "jpeg",
			MIMEType:    "image/jpeg",
			Category:    "image",
			Description: "Joint Photographic Experts Group (ISO/IEC 10918-1)",
			DocURL:      "https://kaijuconverter.com/formats/jpg",
		},
		match: func(h []byte) bool {
			return len(h) >= 3 && h[0] == 0xFF && h[1] == 0xD8 && h[2] == 0xFF
		},
	},
	// 4. GIF
	{
		info: FormatInfo{
			Extension:   "gif",
			MIMEType:    "image/gif",
			Category:    "image",
			Description: "Graphics Interchange Format (GIF87a / GIF89a)",
			DocURL:      "https://kaijuconverter.com/formats/gif",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("GIF87a")) || bytes.HasPrefix(h, []byte("GIF89a"))
		},
	},
	// 5. WEBP (RIFF....WEBP)
	{
		info: FormatInfo{
			Extension:   "webp",
			MIMEType:    "image/webp",
			Category:    "image",
			Description: "WebP Modern Lossy & Lossless Image Container",
			DocURL:      "https://kaijuconverter.com/formats/webp",
		},
		match: func(h []byte) bool {
			return len(h) >= 12 && bytes.Equal(h[0:4], []byte("RIFF")) && bytes.Equal(h[8:12], []byte("WEBP"))
		},
	},
	// 6. AVIF (ISOBMFF with ftyp avif/avis)
	{
		info: FormatInfo{
			Extension:   "avif",
			MIMEType:    "image/avif",
			Category:    "image",
			Description: "AV1 Image File Format (AOMedia)",
			DocURL:      "https://kaijuconverter.com/formats/avif",
		},
		match: func(h []byte) bool {
			if len(h) < 12 || !bytes.Equal(h[4:8], []byte("ftyp")) {
				return false
			}
			brand := string(h[8:12])
			if brand == "avif" || brand == "avis" {
				return true
			}
			limit := len(h)
			if limit > 64 {
				limit = 64
			}
			return bytes.Contains(h[12:limit], []byte("avif"))
		},
	},
	// 7. HEIC / HEIF (ISOBMFF with ftyp heic/heix/mif1/msf1)
	{
		info: FormatInfo{
			Extension:   "heic",
			MIMEType:    "image/heic",
			Category:    "image",
			Description: "High Efficiency Image Container (MPEG-H Part 12 / ISO 23008-12)",
			DocURL:      "https://kaijuconverter.com/formats/heic",
		},
		match: func(h []byte) bool {
			if len(h) < 12 || !bytes.Equal(h[4:8], []byte("ftyp")) {
				return false
			}
			brand := string(h[8:12])
			if brand == "heic" || brand == "heix" || brand == "hevc" || brand == "heim" || brand == "heis" || brand == "mif1" || brand == "msf1" {
				return true
			}
			limit := len(h)
			if limit > 64 {
				limit = 64
			}
			return bytes.Contains(h[12:limit], []byte("heic"))
		},
	},
	// 8. ZIP
	{
		info: FormatInfo{
			Extension:   "zip",
			MIMEType:    "application/zip",
			Category:    "archive",
			Description: "ZIP Archive Container (PKWARE PK0304)",
			DocURL:      "https://kaijuconverter.com/formats/zip",
		},
		match: func(h []byte) bool {
			return len(h) >= 4 && h[0] == 0x50 && h[1] == 0x4B &&
				((h[2] == 0x03 && h[3] == 0x04) || (h[2] == 0x05 && h[3] == 0x06) || (h[2] == 0x07 && h[3] == 0x08))
		},
	},
	// 9. 7Z
	{
		info: FormatInfo{
			Extension:   "7z",
			MIMEType:    "application/x-7z-compressed",
			Category:    "archive",
			Description: "7-Zip Compressed Archive (Igor Pavlov)",
			DocURL:      "https://kaijuconverter.com/formats/7z",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C})
		},
	},
	// 10. RAR
	{
		info: FormatInfo{
			Extension:   "rar",
			MIMEType:    "application/vnd.rar",
			Category:    "archive",
			Description: "Roshal Archive Compressed File (RAR v4 / v5)",
			DocURL:      "https://kaijuconverter.com/formats/rar",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) ||
				bytes.HasPrefix(h, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00})
		},
	},
	// 11. GZIP
	{
		info: FormatInfo{
			Extension:   "gz",
			MIMEType:    "application/gzip",
			Category:    "archive",
			Description: "GNU Zip Compressed Archive (RFC 1952)",
			DocURL:      "https://kaijuconverter.com/formats/gz",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x1F, 0x8B})
		},
	},
	// 12. BZIP2
	{
		info: FormatInfo{
			Extension:   "bz2",
			MIMEType:    "application/x-bzip2",
			Category:    "archive",
			Description: "Bzip2 Burrows-Wheeler Compressed Archive",
			DocURL:      "https://kaijuconverter.com/formats/bz2",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x42, 0x5A, 0x68})
		},
	},
	// 13. XZ
	{
		info: FormatInfo{
			Extension:   "xz",
			MIMEType:    "application/x-xz",
			Category:    "archive",
			Description: "XZ LZMA2 Compression Container",
			DocURL:      "https://kaijuconverter.com/formats/xz",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00})
		},
	},
	// 14. ZSTD
	{
		info: FormatInfo{
			Extension:   "zst",
			MIMEType:    "application/zstd",
			Category:    "archive",
			Description: "Zstandard Real-time Compression Format (RFC 8878)",
			DocURL:      "https://kaijuconverter.com/formats/zst",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x28, 0xB5, 0x2F, 0xFD})
		},
	},
	// 15. MP3
	{
		info: FormatInfo{
			Extension:   "mp3",
			MIMEType:    "audio/mpeg",
			Category:    "audio",
			Description: "MPEG-1 / MPEG-2 Audio Layer III (ID3 Tagged or Sync Frame)",
			DocURL:      "https://kaijuconverter.com/formats/mp3",
		},
		match: func(h []byte) bool {
			if bytes.HasPrefix(h, []byte("ID3")) {
				return true
			}
			return len(h) >= 2 && h[0] == 0xFF && (h[1]&0xE0) == 0xE0
		},
	},
	// 16. FLAC
	{
		info: FormatInfo{
			Extension:   "flac",
			MIMEType:    "audio/flac",
			Category:    "audio",
			Description: "Free Lossless Audio Codec (Xiph.Org / RFC 9619)",
			DocURL:      "https://kaijuconverter.com/formats/flac",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("fLaC"))
		},
	},
	// 17. WAV
	{
		info: FormatInfo{
			Extension:   "wav",
			MIMEType:    "audio/wav",
			Category:    "audio",
			Description: "Waveform Audio File Format (RIFF WAVE)",
			DocURL:      "https://kaijuconverter.com/formats/wav",
		},
		match: func(h []byte) bool {
			return len(h) >= 12 && bytes.Equal(h[0:4], []byte("RIFF")) && bytes.Equal(h[8:12], []byte("WAVE"))
		},
	},
	// 18. OGG
	{
		info: FormatInfo{
			Extension:   "ogg",
			MIMEType:    "audio/ogg",
			Category:    "audio",
			Description: "Ogg Bitstream Container (Vorbis / Opus / Theora)",
			DocURL:      "https://kaijuconverter.com/formats/ogg",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("OggS"))
		},
	},
	// 19. MP4
	{
		info: FormatInfo{
			Extension:   "mp4",
			MIMEType:    "video/mp4",
			Category:    "video",
			Description: "MPEG-4 Part 14 Media Container (ISO/IEC 14496-14)",
			DocURL:      "https://kaijuconverter.com/formats/mp4",
		},
		match: func(h []byte) bool {
			if len(h) < 12 || !bytes.Equal(h[4:8], []byte("ftyp")) {
				return false
			}
			brand := string(h[8:12])
			validBrands := []string{"isom", "iso2", "mp41", "mp42", "dash", "M4V ", "M4A "}
			for _, vb := range validBrands {
				if brand == vb {
					return true
				}
			}
			return false
		},
	},
	// 20. MKV / WEBM
	{
		info: FormatInfo{
			Extension:   "mkv",
			MIMEType:    "video/x-matroska",
			Category:    "video",
			Description: "Matroska Multimedia Container (EBML Specification)",
			DocURL:      "https://kaijuconverter.com/formats/mkv",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x1A, 0x45, 0xDF, 0xA3})
		},
	},
	// 21. AVI
	{
		info: FormatInfo{
			Extension:   "avi",
			MIMEType:    "video/x-msvideo",
			Category:    "video",
			Description: "Audio Video Interleave Container (RIFF AVI)",
			DocURL:      "https://kaijuconverter.com/formats/avi",
		},
		match: func(h []byte) bool {
			return len(h) >= 12 && bytes.Equal(h[0:4], []byte("RIFF")) && bytes.Equal(h[8:12], []byte("AVI "))
		},
	},
	// 22. WASM
	{
		info: FormatInfo{
			Extension:   "wasm",
			MIMEType:    "application/wasm",
			Category:    "binary",
			Description: "WebAssembly Binary Format (W3C Recommendation)",
			DocURL:      "https://kaijuconverter.com/formats/wasm",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x00, 0x61, 0x73, 0x6D})
		},
	},
	// 23. ELF
	{
		info: FormatInfo{
			Extension:   "elf",
			MIMEType:    "application/x-elf",
			Category:    "executable",
			Description: "Executable and Linkable Format (UNIX / Linux Binary)",
			DocURL:      "https://kaijuconverter.com/formats/elf",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x7F, 0x45, 0x4C, 0x46})
		},
	},
	// 24. SQLITE
	{
		info: FormatInfo{
			Extension:   "sqlite",
			MIMEType:    "application/vnd.sqlite3",
			Category:    "database",
			Description: "SQLite 3 Database File Format",
			DocURL:      "https://kaijuconverter.com/formats/sqlite",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("SQLite format 3 "))
		},
	},
	// 25. PARQUET
	{
		info: FormatInfo{
			Extension:   "parquet",
			MIMEType:    "application/vnd.apache.parquet",
			Category:    "data",
			Description: "Apache Parquet Columnar Storage Format",
			DocURL:      "https://kaijuconverter.com/formats/parquet",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("PAR1"))
		},
	},
	// 26. STL
	{
		info: FormatInfo{
			Extension:   "stl",
			MIMEType:    "model/stl",
			Category:    "3d",
			Description: "Stereolithography 3D Mesh (ASCII or Binary)",
			DocURL:      "https://kaijuconverter.com/formats/stl",
		},
		match: func(h []byte) bool {
			if bytes.HasPrefix(h, []byte("solid ")) {
				return true
			}
			// Binary STL: 80 bytes header followed by 4-byte little-endian triangle count
			return len(h) >= 84
		},
	},
	// 27. TTF
	{
		info: FormatInfo{
			Extension:   "ttf",
			MIMEType:    "font/ttf",
			Category:    "font",
			Description: "TrueType Font Specification (Apple / Microsoft)",
			DocURL:      "https://kaijuconverter.com/formats/ttf",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x00, 0x01, 0x00, 0x00}) || bytes.HasPrefix(h, []byte("true"))
		},
	},
	// 28. WOFF2
	{
		info: FormatInfo{
			Extension:   "woff2",
			MIMEType:    "font/woff2",
			Category:    "font",
			Description: "Web Open Font Format 2.0 (W3C Recommendation)",
			DocURL:      "https://kaijuconverter.com/formats/woff2",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("wOF2"))
		},
	},
	// 29. WOFF
	{
		info: FormatInfo{
			Extension:   "woff",
			MIMEType:    "font/woff",
			Category:    "font",
			Description: "Web Open Font Format 1.0 (W3C Recommendation)",
			DocURL:      "https://kaijuconverter.com/formats/woff",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("wOFF"))
		},
	},
	// 30. BMP
	{
		info: FormatInfo{
			Extension:   "bmp",
			MIMEType:    "image/bmp",
			Category:    "image",
			Description: "Windows Bitmap Image Format",
			DocURL:      "https://kaijuconverter.com/formats/bmp",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte("BM"))
		},
	},
	// 31. TIFF
	{
		info: FormatInfo{
			Extension:   "tiff",
			MIMEType:    "image/tiff",
			Category:    "image",
			Description: "Tagged Image File Format (Little or Big Endian)",
			DocURL:      "https://kaijuconverter.com/formats/tiff",
		},
		match: func(h []byte) bool {
			return bytes.HasPrefix(h, []byte{0x49, 0x49, 0x2A, 0x00}) || bytes.HasPrefix(h, []byte{0x4D, 0x4D, 0x00, 0x2A})
		},
	},
}

// DetectMagicBytes examines the binary header of a file (typically first 16 to 128 bytes)
// and identifies its digital format, MIME type, category, and canonical specification URL.
//
// Example:
//
//	header := []byte("%PDF-1.7...")
//	format, ok := kaijuconverter.DetectMagicBytes(header)
//	if ok {
//	    fmt.Printf("Detected %s (%s) -> %s
", format.Extension, format.MIMEType, format.DocURL)
//	}
//
// Supported signatures include PDF, PNG, JPEG, GIF, WEBP, AVIF, HEIC, ZIP, 7Z, RAR,
// GZ, BZ2, XZ, ZSTD, MP3, FLAC, WAV, OGG, MP4, MKV, AVI, WASM, ELF, SQLITE, PARQUET,
// STL, TTF, WOFF2, WOFF, BMP, and TIFF.
//
// For web-based visual analysis and converters, visit:
// https://kaijuconverter.com/tools
func DetectMagicBytes(header []byte) (FormatInfo, bool) {
	for _, rule := range registry {
		if rule.match(header) {
			return rule.info, true
		}
	}
	return FormatInfo{}, false
}

// RegisteredFormats returns a list of all file formats supported by the magic byte signature engine.
func RegisteredFormats() []FormatInfo {
	res := make([]FormatInfo, len(registry))
	for i, r := range registry {
		res[i] = r.info
	}
	return res
}

// Client provides an idiomatic HTTP client for interacting with KaijuConverter.com REST and MCP APIs.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// ClientOption defines a functional option for configuring a Client.
type ClientOption func(*Client)

// WithBaseURL overrides the default endpoint (https://kaijuconverter.com).
func WithBaseURL(rawURL string) ClientOption {
	return func(c *Client) {
		c.BaseURL = strings.TrimRight(rawURL, "/")
	}
}

// WithAPIKey sets an optional authentication token for authenticated API endpoints.
func WithAPIKey(key string) ClientOption {
	return func(c *Client) {
		c.APIKey = key
	}
}

// WithHTTPClient configures a custom *http.Client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient != nil {
			c.HTTPClient = httpClient
		}
	}
}

// NewClient creates a configured KaijuConverter API client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		BaseURL: DefaultBaseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GetFormats queries https://kaijuconverter.com/api/v1/formats to fetch full catalog metadata.
func (c *Client) GetFormats(ctx context.Context) ([]FormatInfo, error) {
	reqURL := fmt.Sprintf("%s%s", c.BaseURL, APIEndpointFormats)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("kaiju: create request: %w", err)
	}
	req.Header.Set("User-Agent", "kaijuconverter-go/1.0.0 (+https://kaijuconverter.com)")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kaiju: request formats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("kaiju: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Formats []FormatInfo `json:"formats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("kaiju: decode formats: %w", err)
	}
	return result.Formats, nil
}

// GetFormat queries https://kaijuconverter.com/api/v1/formats/{extension} for single format specs.
func (c *Client) GetFormat(ctx context.Context, ext string) (*FormatInfo, error) {
	cleanExt := strings.ToLower(strings.TrimPrefix(ext, "."))
	reqURL := fmt.Sprintf("%s%s/%s", c.BaseURL, APIEndpointFormats, url.PathEscape(cleanExt))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("kaiju: create request: %w", err)
	}
	req.Header.Set("User-Agent", "kaijuconverter-go/1.0.0 (+https://kaijuconverter.com)")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kaiju: request format %s: %w", cleanExt, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("kaiju: format %s returned status %d: %s", cleanExt, resp.StatusCode, string(body))
	}

	var info FormatInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("kaiju: decode format %s: %w", cleanExt, err)
	}
	return &info, nil
}

// MCPRequest defines the payload for Model Context Protocol tool execution.
type MCPRequest struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
}

// MCPResponse defines the response payload returned by the MCP endpoint.
type MCPResponse struct {
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// CallMCP sends a tool invocation request to the KaijuConverter Model Context Protocol endpoint
// at https://kaijuconverter.com/api/mcp.
func (c *Client) CallMCP(ctx context.Context, tool string, args map[string]interface{}) (map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s%s", c.BaseURL, APIEndpointMCP)
	payload := MCPRequest{
		Tool:      tool,
		Arguments: args,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kaiju: marshal mcp request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("kaiju: create mcp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kaijuconverter-go/1.0.0 (+https://kaijuconverter.com/integrations)")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kaiju: do mcp request: %w", err)
	}
	defer resp.Body.Close()

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("kaiju: decode mcp response: %w", err)
	}
	if !mcpResp.Success {
		return nil, fmt.Errorf("kaiju: mcp error: %s", mcpResp.Error)
	}
	return mcpResp.Result, nil
}
