// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

var update = flag.Bool("update", false, "rewrite the payload of every vector in testdata/format/vectors.json")

const vectorsPath = "../../testdata/format/vectors.json"

func newCodec(t *testing.T) *Codec {
	t.Helper()
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// seeded returns a codec whose salts and IVs come from the given bytes, in the
// order Encrypt asks for them: the salt first, then the IV.
func seeded(t *testing.T, parts ...[]byte) *Codec {
	t.Helper()
	c := newCodec(t)
	c.rand = bytes.NewReader(slices.Concat(parts...))
	return c
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func sequence(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

type vectorContent struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
	Name string `json:"name"`
	Mime string `json:"mime"`
	Data string `json:"data"`
}

type vector struct {
	Name       string        `json:"name"`
	LinkKey    string        `json:"linkKey"`
	Passphrase string        `json:"passphrase"`
	Salt       string        `json:"salt"`
	IV         string        `json:"iv"`
	Content    vectorContent `json:"content"`
	Payload    string        `json:"payload"`
}

func (v vector) content(t *testing.T) Content {
	t.Helper()
	if v.Content.Kind == string(KindText) {
		return Content{Kind: KindText, Text: v.Content.Text}
	}
	data, err := DecodeBase64(v.Content.Data)
	if err != nil {
		t.Fatalf("vector %q: %v", v.Name, err)
	}
	return Content{Kind: KindFile, Name: v.Content.Name, Mime: v.Content.Mime, Data: data}
}

func loadVectors(t *testing.T) ([]byte, []vector) {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return raw, file.Vectors
}

// setPayload replaces the payload value that follows the named vector, and
// touches nothing else, so a combining character in the file stays as written.
func setPayload(t *testing.T, raw []byte, name, payload string) []byte {
	t.Helper()
	text := string(raw)
	at := strings.Index(text, `"name": `+`"`+name+`"`)
	if at < 0 {
		t.Fatalf("vector %q not found in the file", name)
	}
	const key = `"payload": "`
	start := strings.Index(text[at:], key)
	if start < 0 {
		t.Fatalf("vector %q has no payload field", name)
	}
	start += at + len(key)
	end := start + strings.Index(text[start:], `"`)
	return []byte(text[:start] + payload + text[end:])
}

// TestVectors is the Go half of the cross language check. The same file is
// read by web/src/lib/crypto-vectors.test.ts, which has to agree on every
// byte. A change to the format fails one side or both.
func TestVectors(t *testing.T) {
	raw, vectors := loadVectors(t)
	updated := raw
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			key := mustHex(t, v.LinkKey)
			content := v.content(t)
			c := seeded(t, mustHex(t, v.Salt), mustHex(t, v.IV))
			sealed, err := c.Encrypt(content, key, v.Passphrase)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if *update {
				updated = setPayload(t, updated, v.Name, EncodeBase64(sealed))
				return
			}
			want, err := DecodeBase64(v.Payload)
			if err != nil {
				t.Fatalf("payload field: %v", err)
			}
			if !bytes.Equal(sealed, want) {
				t.Errorf("Encrypt with fixed salt and iv differs from the golden payload\n got %s\nwant %s",
					EncodeBase64(sealed), v.Payload)
			}
			got, err := newCodec(t).Decrypt(want, key, v.Passphrase)
			if err != nil {
				t.Fatalf("Decrypt the golden payload: %v", err)
			}
			if got.Kind != content.Kind || got.Text != content.Text || got.Name != content.Name ||
				got.Mime != content.Mime || !bytes.Equal(got.Data, content.Data) {
				t.Errorf("Decrypt returned other content than the vector holds")
			}
		})
	}
	if *update {
		if err := os.WriteFile(vectorsPath, updated, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
	}
}

// A normalising editor could collapse the decomposed passphrase into the
// precomposed one and leave the vector passing no matter what each side does.
func TestVectors_keepADecomposedPassphrase(t *testing.T) {
	_, vectors := loadVectors(t)
	for _, v := range vectors {
		if v.Passphrase != "" && v.Passphrase != norm.NFC.String(v.Passphrase) {
			return
		}
	}
	t.Error("no vector carries a passphrase that differs from its NFC form")
}

func TestNew(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	if c.KeyBytes() != 32 {
		t.Errorf("KeyBytes() = %d, want 32", c.KeyBytes())
	}
	key, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, _ := c.GenerateKey()
	if len(key) != 32 || bytes.Equal(key, other) {
		t.Errorf("link keys must be 32 distinct random bytes")
	}
}

func TestCodec_roundTrip(t *testing.T) {
	t.Parallel()
	binary := make([]byte, 70000)
	for i := range binary {
		binary[i] = byte(i*31 + 7)
	}
	tests := []struct {
		name       string
		content    Content
		passphrase string
		wantLen    int
	}{
		{"short text", Content{Kind: KindText, Text: "hunter2"}, "", 2 + 12 + 256 + 16},
		{"empty text", Content{Kind: KindText}, "", 2 + 12 + 256 + 16},
		{"text with markup characters", Content{Kind: KindText, Text: `<a href="x">&</a> ✓`}, "", 2 + 12 + 256 + 16},
		{"large file", Content{Kind: KindFile, Name: "../id_ed25519", Mime: "application/x-pem-file", Data: binary}, "", 0},
		{"empty file", Content{Kind: KindFile, Name: "empty", Mime: ""}, "", 2 + 12 + 256 + 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCodec(t)
			key, err := c.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := c.Encrypt(tt.content, key, tt.passphrase)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if tt.wantLen != 0 && len(sealed) != tt.wantLen {
				t.Errorf("payload is %d bytes, want %d", len(sealed), tt.wantLen)
			}
			got, err := c.Decrypt(sealed, key, tt.passphrase)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got.Kind != tt.content.Kind || got.Text != tt.content.Text || got.Name != tt.content.Name ||
				got.Mime != tt.content.Mime || !bytes.Equal(got.Data, tt.content.Data) {
				t.Errorf("content changed on the way")
			}
		})
	}
}

func TestCodec_passphrase(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 1)
	content := Content{Kind: KindText, Text: "behind a passphrase"}
	sealed, err := c.Encrypt(content, key, "tr0ub4dor&3")
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 2+16+12+256+16 {
		t.Errorf("payload is %d bytes, want %d", len(sealed), 2+16+12+256+16)
	}
	needs, err := c.NeedsPassphrase(sealed)
	if err != nil || !needs {
		t.Fatalf("NeedsPassphrase = %v, %v, want true", needs, err)
	}
	tests := []struct {
		name       string
		key        []byte
		passphrase string
		wantErr    error
	}{
		{"both factors", key, "tr0ub4dor&3", nil},
		{"missing passphrase", key, "", ErrPassphraseRequired},
		{"wrong case", key, "Tr0ub4dor&3", ErrFailed},
		{"wrong link key", sequence(32, 9), "tr0ub4dor&3", ErrFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Decrypt(sealed, tt.key, tt.passphrase)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Decrypt error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCodec_passphraseIsNormalised(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 1)
	precomposed, decomposed := "Café", "Café"
	if precomposed == decomposed {
		t.Fatal("the two spellings must differ as bytes")
	}
	sealed, err := c.Encrypt(Content{Kind: KindText, Text: "x"}, key, precomposed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(sealed, key, decomposed); err != nil {
		t.Errorf("the decomposed spelling must open it: %v", err)
	}
}

func TestCodec_rejectsInvalidInput(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 1)
	tests := []struct {
		name       string
		content    Content
		key        []byte
		passphrase string
	}{
		{"link key of 31 bytes", Content{Kind: KindText, Text: "x"}, key[:31], ""},
		{"no link key", Content{Kind: KindText, Text: "x"}, nil, ""},
		{"text that is not UTF-8", Content{Kind: KindText, Text: "a\xffb"}, key, ""},
		{"unknown kind", Content{Kind: "html", Text: "<b>"}, key, ""},
		{"passphrase that is not UTF-8", Content{Kind: KindText, Text: "x"}, key, "a\xffb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Encrypt(tt.content, tt.key, tt.passphrase)
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("Encrypt error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestCodec_Decrypt_refusesDamagedPayloads(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 1)
	plain, err := c.Encrypt(Content{Kind: KindText, Text: "x"}, key, "")
	if err != nil {
		t.Fatal(err)
	}
	flip := func(p []byte, i int, mask byte) []byte {
		out := slices.Clone(p)
		out[i] ^= mask
		return out
	}
	withByte := func(p []byte, i int, b byte) []byte {
		out := slices.Clone(p)
		out[i] = b
		return out
	}
	tests := []struct {
		name    string
		payload []byte
		key     []byte
		wantErr error
	}{
		{"empty payload", nil, key, ErrMalformed},
		{"one byte", []byte{1}, key, ErrMalformed},
		{"header only", plain[:20], key, ErrMalformed},
		{"unknown version", withByte(plain, 0, 2), key, ErrUnsupported},
		{"unknown flags", withByte(plain, 1, 0x80), key, ErrUnsupported},
		{"flag added to a payload without a salt", withByte(plain, 1, 1), key, ErrPassphraseRequired},
		{"flipped iv", flip(plain, 13, 1), key, ErrFailed},
		{"flipped ciphertext", flip(plain, 14, 0x80), key, ErrFailed},
		{"flipped tag", flip(plain, len(plain)-1, 0x80), key, ErrFailed},
		{"truncated tag", plain[:len(plain)-1], key, ErrFailed},
		{"trailing byte", append(slices.Clone(plain), 0), key, ErrFailed},
		{"wrong link key", plain, sequence(32, 2), ErrFailed},
		{"link key of 31 bytes", plain, key[:31], ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Decrypt(tt.payload, tt.key, "")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Decrypt error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCodec_Decrypt_refusesAFlippedPassphraseHeader(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 1)
	sealed, err := c.Encrypt(Content{Kind: KindText, Text: "x"}, key, "pass")
	if err != nil {
		t.Fatal(err)
	}
	stripped := slices.Clone(sealed)
	stripped[1] = 0
	if _, err := c.Decrypt(stripped, key, "pass"); !errors.Is(err, ErrFailed) {
		t.Errorf("flag removed: error = %v, want ErrFailed", err)
	}
	for _, i := range []int{2, 17, 18, 29} {
		tampered := slices.Clone(sealed)
		tampered[i] ^= 1
		if _, err := c.Decrypt(tampered, key, "pass"); !errors.Is(err, ErrFailed) {
			t.Errorf("byte %d flipped: error = %v, want ErrFailed", i, err)
		}
	}
}

// sealV1 builds a payload straight from the documented layout with the
// standard library alone and the literal numbers of format.json. It calls
// nothing from the package under test, so it pins the contract instead of
// agreeing with whatever the package happens to do.
func sealV1(t *testing.T, linkKey []byte, passphrase string, plaintext []byte) []byte {
	t.Helper()
	ikm := slices.Clone(linkKey)
	var salt []byte
	if passphrase != "" {
		salt = sequence(16, 0x40)
		stretched, err := pbkdf2.Key(sha256.New, passphrase, salt, 600000, 32)
		if err != nil {
			t.Fatal(err)
		}
		ikm = append(ikm, stretched...)
	}
	aesKey, err := hkdf.Key(sha256.New, ikm, salt, "burnlink.de v1 aes-256-gcm", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := sequence(12, 0x70)
	flags := byte(0)
	if passphrase != "" {
		flags = 1
	}
	head := slices.Concat([]byte{1, flags}, salt, iv)
	return gcm.Seal(slices.Clone(head), iv, plaintext, head)
}

func TestCodec_Decrypt_opensAPayloadBuiltFromTheDocumentedFormat(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 3)
	t.Run("without a passphrase", func(t *testing.T) {
		t.Parallel()
		sealed := sealV1(t, key, "", []byte(`{"type":"text","text":"from the spec"}   `))
		got, err := c.Decrypt(sealed, key, "")
		if err != nil || got.Text != "from the spec" {
			t.Errorf("Decrypt = %+v, %v", got, err)
		}
	})
	t.Run("with a passphrase", func(t *testing.T) {
		t.Parallel()
		sealed := sealV1(t, key, "tr0ub4dor&3", []byte(`{"type":"text","text":"behind a passphrase"}`))
		if sealed[1] != 1 {
			t.Fatalf("the documented flags byte for a passphrase is 1, got %d", sealed[1])
		}
		got, err := c.Decrypt(sealed, key, "tr0ub4dor&3")
		if err != nil || got.Text != "behind a passphrase" {
			t.Errorf("Decrypt = %+v, %v", got, err)
		}
	})
	t.Run("what Encrypt wrote opens with the documented reader", func(t *testing.T) {
		t.Parallel()
		sealed, err := c.Encrypt(Content{Kind: KindText, Text: "hello"}, key, "")
		if err != nil {
			t.Fatal(err)
		}
		block, _ := aes.NewCipher(mustDerive(t, key))
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, sealed[2:14], sealed[14:], sealed[:14])
		if err != nil {
			t.Fatalf("the documented reader refused the payload: %v", err)
		}
		if !bytes.HasPrefix(plain, []byte(`{"type":"text","text":"hello"}`)) {
			t.Errorf("plaintext does not start with the documented JSON")
		}
	})
}

func mustDerive(t *testing.T, key []byte) []byte {
	t.Helper()
	derived, err := hkdf.Key(sha256.New, key, nil, "burnlink.de v1 aes-256-gcm", 32)
	if err != nil {
		t.Fatal(err)
	}
	return derived
}

func TestCodec_Decrypt_refusesAuthenticPlaintextOfTheWrongShape(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 3)
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"unknown type", []byte(`{"type":"html","text":"<img src=x onerror=alert(1)>"}`)},
		{"text that is a number", []byte(`{"type":"text","text":5}`)},
		{"text missing", []byte(`{"type":"text"}`)},
		{"file data that is not base64", []byte(`{"type":"file","name":"a","mime":"text/plain","data":"not base64!"}`)},
		{"file name that is a list", []byte(`{"type":"file","name":["a"],"mime":"text/plain","data":"AAAA"}`)},
		{"file mime missing", []byte(`{"type":"file","name":"a","data":"AAAA"}`)},
		{"null", []byte(`null`)},
		{"list", []byte(`[]`)},
		{"not json", []byte(`not json`)},
		{"invalid UTF-8", []byte{0x7b, 0xff, 0xfe, 0x7d}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Decrypt(sealV1(t, key, "", tt.plaintext), key, "")
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("Decrypt error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestCodec_Decrypt_dropsALeadingByteOrderMark(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	key := sequence(32, 3)
	plain := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"type":"text","text":"bom"}`)...)
	got, err := c.Decrypt(sealV1(t, key, "", plain), key, "")
	if err != nil || got.Text != "bom" {
		t.Errorf("Decrypt = %+v, %v", got, err)
	}
}

// The two fixtures were built outside both implementations, for a link the
// predecessor issued. web/src/lib/crypto.test.ts opens the same files.
func TestCodec_Decrypt_opensLinksIssuedByThePredecessor(t *testing.T) {
	t.Parallel()
	c := newCodec(t)
	dir := filepath.Join("..", "..", "web", "src", "lib", "testdata")
	tests := []struct {
		name       string
		file       string
		key        []byte
		passphrase string
		want       string
	}{
		{"plain", "old-burnlink-text.v1", sequence(32, 0), "", "a secret the predecessor already sent"},
		{"with a passphrase", "old-burnlink-text-with-passphrase.v1", reversed(32), "correct horse battery staple", "a secret that needed a passphrase"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(dir, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Decrypt(raw, tt.key, tt.passphrase)
			if err != nil || got.Kind != KindText || got.Text != tt.want {
				t.Errorf("Decrypt = %+v, %v", got, err)
			}
		})
	}
}

func reversed(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(n - 1 - i)
	}
	return b
}

func TestDecodeBase64URL(t *testing.T) {
	t.Parallel()
	key := EncodeBase64URL(sequence(32, 0))
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"canonical key", key, false},
		{"empty", "", false},
		{"padding", key + "=", true},
		{"standard alphabet", key[:42] + "+", true},
		{"space", key + " ", true},
		{"newline", key + "\n", true},
		{"carriage return in the middle", key[:10] + "\r" + key[10:], true},
		{"one character", "A", true},
		{"non canonical trailing bits", key[:42] + "B", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeBase64URL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64URL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Errorf("error %v does not wrap ErrMalformed", err)
			}
		})
	}
	if len(key) != 43 {
		t.Errorf("a link key encodes to %d characters, want 43", len(key))
	}
}

func TestDecodeBase64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"padded", "AAEC/v9/gA==", false},
		{"empty", "", false},
		{"missing padding", "AAA", true},
		{"padding in the middle", "AA=A", true},
		{"non canonical trailing bits", "AB==", true},
		{"url alphabet", "A-_A", true},
		{"newline", "AAAA\n", true},
		{"newline in the middle", "AA\nA", true},
		{"three padding characters", "A===", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
