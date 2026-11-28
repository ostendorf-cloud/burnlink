// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Kind tells what a secret holds.
type Kind string

// The two kinds of content the page knows.
const (
	KindText Kind = "text"
	KindFile Kind = "file"
)

// Content is what a secret holds: a text, or a file with its bytes.
// Name and Mime are the sender's words, so a caller treats them as data.
type Content struct {
	Kind Kind
	Text string
	Name string
	Mime string
	Data []byte
}

// The key order matches what JSON.stringify writes on the page.
type textJSON struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type fileJSON struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Mime string `json:"mime"`
	Data string `json:"data"`
}

// encodeContent returns the JSON of content, padded with spaces to a multiple
// of the pad block. JSON parsers ignore trailing white space, so the padding
// needs no length field of its own.
func (c *Codec) encodeContent(content Content) ([]byte, error) {
	var v any
	switch content.Kind {
	case KindText:
		if !utf8.ValidString(content.Text) {
			return nil, fmt.Errorf("%w: text is not valid UTF-8", ErrMalformed)
		}
		v = textJSON{Type: string(KindText), Text: content.Text}
	case KindFile:
		if !utf8.ValidString(content.Name) || !utf8.ValidString(content.Mime) {
			return nil, fmt.Errorf("%w: file name or type is not valid UTF-8", ErrMalformed)
		}
		v = fileJSON{Type: string(KindFile), Name: content.Name, Mime: content.Mime, Data: EncodeBase64(content.Data)}
	default:
		return nil, fmt.Errorf("%w: unknown content kind", ErrMalformed)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The page does not escape < > &, so neither does this side.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode content: %w", err)
	}
	encoded := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	size := (len(encoded) + c.spec.PadBlock) / c.spec.PadBlock * c.spec.PadBlock
	padded := bytes.Repeat([]byte{0x20}, size)
	copy(padded, encoded)
	return padded, nil
}

// decodeContent mirrors the page: the bytes are strict UTF-8, and authentic
// plaintext is still something someone else wrote, so nothing is trusted
// beyond the two shapes this version knows.
func decodeContent(plain []byte) (Content, error) {
	// TextDecoder drops a leading byte order mark, so this side does too.
	plain = bytes.TrimPrefix(plain, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(plain) {
		return Content{}, fmt.Errorf("%w: plaintext is not UTF-8", ErrMalformed)
	}
	var obj map[string]any
	if err := json.Unmarshal(plain, &obj); err != nil || obj == nil {
		return Content{}, fmt.Errorf("%w: plaintext is not a JSON object", ErrMalformed)
	}
	switch obj["type"] {
	case string(KindText):
		if text, ok := obj["text"].(string); ok {
			return Content{Kind: KindText, Text: text}, nil
		}
	case string(KindFile):
		name, okName := obj["name"].(string)
		mime, okMime := obj["mime"].(string)
		data, okData := obj["data"].(string)
		if okName && okMime && okData {
			raw, err := DecodeBase64(data)
			if err != nil {
				return Content{}, err
			}
			return Content{Kind: KindFile, Name: name, Mime: mime, Data: raw}, nil
		}
	}
	return Content{}, fmt.Errorf("%w: unknown content", ErrMalformed)
}
