// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ostendorf-cloud/burnlink/internal/payload"
)

// fakeServer implements the three calls the commands make, with the
// semantics that matter: a stored secret opens once and is then gone.
type fakeServer struct {
	srv *httptest.Server

	mu        sync.Mutex
	secrets   map[string][]byte
	requests  strings.Builder
	maxBytes  int
	opens     int
	stores    int
	lifetimes []int64
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{secrets: map[string][]byte{}, maxBytes: 1 << 20}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body bytes.Buffer
	_, _ = body.ReadFrom(r.Body)
	// Everything the server could ever see, for the checks that no key or
	// passphrase went over the wire.
	fmt.Fprintf(&f.requests, "%s %s %v %s\n", r.Method, r.URL.String(), r.Header, body.String())

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
		_, _ = fmt.Fprintf(w, `{"maxCiphertextBytes":%d,"lifetime":{"minSeconds":60,"maxSeconds":604800,"defaultSeconds":86400}}`, f.maxBytes)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets":
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		var req struct {
			Ciphertext      string `json:"ciphertext"`
			LifetimeSeconds *int64 `json:"lifetimeSeconds"`
		}
		if err := json.Unmarshal(body.Bytes(), &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := payload.DecodeBase64(req.Ciphertext)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.stores++
		if req.LifetimeSeconds != nil {
			f.lifetimes = append(f.lifetimes, *req.LifetimeSeconds)
		}
		id := fmt.Sprintf("id%d", f.stores)
		f.secrets[id] = raw
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"id":%q,"expiresAt":"2030-01-02T03:04:05Z"}`, id)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/open"):
		f.opens++
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/"), "/open")
		raw, ok := f.secrets[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"secret not available"}}`))
			return
		}
		delete(f.secrets, id)
		_ = json.NewEncoder(w).Encode(map[string]string{"ciphertext": payload.EncodeBase64(raw)})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeServer) seen() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests.String()
}

func (f *fakeServer) held() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.secrets)
}

func (f *fakeServer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Count(f.requests.String(), "\n")
}

// put stores a payload under an id, as another client would have.
func (f *fakeServer) put(id string, sealed []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[id] = sealed
}

// Format characters a file name or a text may carry, built from code points so
// the source stays readable.
var (
	lre  = string(rune(0x202a)) // left to right embedding
	rlo  = string(rune(0x202e)) // right to left override
	zwsp = string(rune(0x200b)) // zero width space
)

type result struct {
	code           int
	stdout, stderr string
}

type options struct {
	stdin    string
	env      map[string]string
	terminal bool
	workDir  string
}

func run(t *testing.T, f *fakeServer, opts options, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env := Env{
		Stdin:            strings.NewReader(opts.stdin),
		Stdout:           &stdout,
		Stderr:           &stderr,
		Getenv:           func(k string) string { return opts.env[k] },
		StdoutIsTerminal: opts.terminal,
		WorkDir:          opts.workDir,
	}
	if f != nil {
		env.HTTP = f.srv.Client()
	}
	code := Run(context.Background(), args, env)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func link(t *testing.T, r result) string {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("send failed with %d: %s", r.code, r.stderr)
	}
	if strings.Count(r.stdout, "\n") != 1 || !strings.HasSuffix(r.stdout, "\n") {
		t.Fatalf("stdout must be exactly the link and a newline, got %q", r.stdout)
	}
	return strings.TrimSuffix(r.stdout, "\n")
}

func keyOf(t *testing.T, raw string) string {
	t.Helper()
	_, key, ok := strings.Cut(raw, "#")
	if !ok || key == "" {
		t.Fatalf("link has no fragment: %q", raw)
	}
	return key
}

func TestSendAndOpen_text(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	const text = "line one\nline two with ✓ and <b>markup</b>"
	l := link(t, run(t, f, options{stdin: text}, "send", "--server", f.srv.URL))
	if !strings.HasPrefix(l, f.srv.URL+"/s/id1#") {
		t.Errorf("link = %q, want the page's /s/<id>#<key> shape", l)
	}

	got := run(t, f, options{}, "open", l)
	if got.code != 0 || got.stdout != text {
		t.Errorf("open = %d %q (stderr %q), want the exact text", got.code, got.stdout, got.stderr)
	}

	again := run(t, f, options{}, "open", l)
	if again.code != 1 || !strings.Contains(again.stderr, "not available") || again.stdout != "" {
		t.Errorf("second open = %d %q %q, want a refusal that prints nothing", again.code, again.stdout, again.stderr)
	}
}

func TestSend_neverShowsTheKeyOrTheContentOutsideTheLink(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	const text = "a plain text only the receiver may read"
	const pass = "some passphrase value"
	r := run(t, f, options{stdin: text, env: map[string]string{EnvPassphrase: pass}}, "send", "--server", f.srv.URL)
	l := link(t, r)
	key := keyOf(t, l)
	for name, haystack := range map[string]string{"stderr": r.stderr, "server": f.seen()} {
		for what, needle := range map[string]string{"key": key, "text": text, "passphrase": pass} {
			if strings.Contains(haystack, needle) {
				t.Errorf("%s contains the %s", name, what)
			}
		}
	}
}

func TestSendAndOpen_passphrase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	other := filepath.Join(dir, "other")
	writeFile(t, good, "the right words\n")
	writeFile(t, other, "other words\r\n")

	tests := []struct {
		name    string
		send    options
		sendArg []string
		open    options
		openArg []string
		want    int
	}{
		{
			"environment value",
			options{env: map[string]string{EnvPassphrase: "the right words"}},
			nil,
			options{env: map[string]string{EnvPassphrase: "the right words"}},
			nil, 0,
		},
		{
			"file given by flag, newline trimmed",
			options{},
			[]string{"--passphrase-file", good},
			options{},
			[]string{"--passphrase-file", good},
			0,
		},
		{
			"file given by environment",
			options{env: map[string]string{EnvPassphraseFile: good}},
			nil,
			options{env: map[string]string{EnvPassphrase: "the right words"}},
			nil, 0,
		},
		{
			"flag beats the file variable beats the value",
			options{env: map[string]string{EnvPassphraseFile: other, EnvPassphrase: "x"}},
			[]string{"--passphrase-file", good},
			options{env: map[string]string{EnvPassphraseFile: good, EnvPassphrase: "y"}},
			nil, 0,
		},
		{
			"wrong passphrase",
			options{env: map[string]string{EnvPassphrase: "the right words"}},
			nil,
			options{env: map[string]string{EnvPassphrase: "the wrong words"}},
			nil, 1,
		},
		{
			"no passphrase",
			options{env: map[string]string{EnvPassphrase: "the right words"}},
			nil,
			options{},
			nil, 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeServer(t)
			send := tt.send
			send.stdin = "protected text"
			l := link(t, run(t, f, send, append([]string{"send", "--server", f.srv.URL}, tt.sendArg...)...))
			got := run(t, f, tt.open, append(append([]string{"open"}, tt.openArg...), l)...)
			if got.code != tt.want {
				t.Fatalf("open = %d (%s), want %d", got.code, got.stderr, tt.want)
			}
			if tt.want == 0 && got.stdout != "protected text" {
				t.Errorf("open printed %q", got.stdout)
			}
			if tt.want != 0 {
				if got.stdout != "" {
					t.Errorf("a failed open printed %q", got.stdout)
				}
				if !strings.Contains(got.stderr, "already deleted") {
					t.Errorf("stderr %q must say the secret is gone", got.stderr)
				}
				for _, leak := range []string{"the right words", "the wrong words"} {
					if strings.Contains(got.stderr, leak) {
						t.Errorf("stderr repeats a passphrase")
					}
				}
			}
		})
	}
}

func TestSend_hasNoPassphraseFlag(t *testing.T) {
	t.Parallel()
	for _, cmd := range [][]string{{"send", "--passphrase", "x"}, {"open", "--passphrase", "x", "https://burnlink.de/s/a#b"}} {
		r := run(t, nil, options{stdin: "x"}, cmd...)
		if r.code != 2 {
			t.Errorf("%v exited with %d, want 2", cmd[:1], r.code)
		}
	}
}

func TestSend_refusesAnEmptyPassphraseFile(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "empty")
	writeFile(t, path, "\n")
	r := run(t, f, options{stdin: "text"}, "send", "--server", f.srv.URL, "--passphrase-file", path)
	if r.code != 1 || r.stdout != "" || f.held() != 0 {
		t.Errorf("send = %d %q, held %d: an empty passphrase file must not downgrade to no passphrase", r.code, r.stdout, f.held())
	}
}

func TestSendAndOpen_file(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "id_ed25519")
	data := []byte{0, 1, 2, 0xfe, 0xff, '\n', 0x80}
	writeBytes(t, src, data)

	l := link(t, run(t, f, options{}, "send", "--server", f.srv.URL, "--file", src))
	out := t.TempDir()
	r := run(t, f, options{workDir: out}, "open", l)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("open = %d %q %q", r.code, r.stdout, r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(out, "id_ed25519"))
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("saved file = %v, %v, want the original bytes", got, err)
	}
	info, _ := os.Stat(filepath.Join(out, "id_ed25519"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("saved file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSend_fileOptions(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	src := filepath.Join(t.TempDir(), "notes.txt")
	writeFile(t, src, "notes")
	l := link(t, run(t, f, options{}, "send", "--server", f.srv.URL, "--file", src, "--name", "renamed.md", "--mime", "text/markdown"))
	codec, _ := payload.New()
	parsed := parseTestLink(t, l)
	content, err := codec.Decrypt(f.secrets["id1"], parsed, "")
	if err != nil {
		t.Fatal(err)
	}
	if content.Kind != payload.KindFile || content.Name != "renamed.md" || content.Mime != "text/markdown" || string(content.Data) != "notes" {
		t.Errorf("content = %+v", content)
	}
}

func parseTestLink(t *testing.T, l string) []byte {
	t.Helper()
	key, err := payload.DecodeBase64URL(keyOf(t, l))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOpen_savesAHostileFileNameInsideTheDirectoryOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sent string
		want string
	}{
		{"parent traversal", "../../escape.txt", ".._.._escape.txt"},
		{"absolute path", "/etc/cron.d/job", "_etc_cron.d_job"},
		{"windows path", `..\..\escape.txt`, ".._.._escape.txt"},
		{"drive and stream", "C:evil.txt:stream", "C_evil.txt_stream"},
		{"terminal escape", "a\x1b[31mb.txt", "a_[31mb.txt"},
		{"bidi override", "txt" + rlo + "gpj.exe", "txtgpj.exe"},
		{"only dots", "..", "secret"},
		{"empty", "", "secret"},
		{"device name", "NUL.txt", "_NUL.txt"},
		{"trailing dot", "report.", "report"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeServer(t)
			codec, _ := payload.New()
			key, _ := codec.GenerateKey()
			sealed, err := codec.Encrypt(payload.Content{Kind: payload.KindFile, Name: tt.sent, Mime: "x/y", Data: []byte("d")}, key, "")
			if err != nil {
				t.Fatal(err)
			}
			f.put("hostile", sealed)
			parent := t.TempDir()
			out := filepath.Join(parent, "out")
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			l := f.srv.URL + "/s/hostile#" + payload.EncodeBase64URL(key)
			r := run(t, f, options{workDir: out}, "open", l)
			if r.code != 0 {
				t.Fatalf("open = %d %s", r.code, r.stderr)
			}
			entries, _ := os.ReadDir(out)
			if len(entries) != 1 || entries[0].Name() != tt.want {
				t.Errorf("directory holds %v, want exactly %q", names(entries), tt.want)
			}
			siblings, _ := os.ReadDir(parent)
			if len(siblings) != 1 {
				t.Errorf("something was written beside the output directory: %v", names(siblings))
			}
		})
	}
}

func names(entries []os.DirEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestOpen_neverReplacesAFile(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	src := filepath.Join(t.TempDir(), "data.bin")
	writeFile(t, src, "payload")
	out := t.TempDir()
	taken := filepath.Join(out, "data.bin")
	writeFile(t, taken, "mine")
	l := link(t, run(t, f, options{}, "send", "--server", f.srv.URL, "--file", src))
	if r := run(t, f, options{workDir: out}, "open", l); r.code != 0 {
		t.Fatalf("open = %d %s", r.code, r.stderr)
	}
	if got, _ := os.ReadFile(taken); string(got) != "mine" {
		t.Errorf("an existing file was replaced")
	}
	if got, _ := os.ReadFile(filepath.Join(out, "data-1.bin")); string(got) != "payload" {
		t.Errorf("the content did not land under the next free name")
	}
}

func TestOpen_checksTheDestinationBeforeSpendingTheSecret(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	l := link(t, run(t, f, options{stdin: "keep me"}, "send", "--server", f.srv.URL))
	taken := filepath.Join(t.TempDir(), "taken")
	writeFile(t, taken, "mine")
	r := run(t, f, options{}, "open", "--out", taken, l)
	if r.code != 1 || f.opens != 0 || f.held() != 1 {
		t.Errorf("open = %d, opens %d, held %d: an existing destination must fail before the server is asked", r.code, f.opens, f.held())
	}
	if got, _ := os.ReadFile(taken); string(got) != "mine" {
		t.Errorf("the existing file changed")
	}
}

func TestOpen_outPath(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	l := link(t, run(t, f, options{stdin: "to a file"}, "send", "--server", f.srv.URL))
	dest := filepath.Join(t.TempDir(), "secret.out")
	r := run(t, f, options{}, "open", "--out", dest, l)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("open = %d %q %q", r.code, r.stdout, r.stderr)
	}
	if got, _ := os.ReadFile(dest); string(got) != "to a file" {
		t.Errorf("file holds %q", got)
	}
}

func TestOpen_removesTheReservedFileWhenOpeningFails(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	dest := filepath.Join(t.TempDir(), "never-filled")
	r := run(t, f, options{}, "open", "--out", dest, f.srv.URL+"/s/nothing#"+payload.EncodeBase64URL(make([]byte, 32)))
	if r.code != 1 {
		t.Fatalf("open = %d", r.code)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("an empty file was left behind: %v", err)
	}
}

func TestOpen_linkFromStandardInput(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	l := link(t, run(t, f, options{stdin: "via stdin"}, "send", "--server", f.srv.URL))
	r := run(t, f, options{stdin: l + "\n"}, "open", "-")
	if r.code != 0 || r.stdout != "via stdin" {
		t.Errorf("open = %d %q %q", r.code, r.stdout, r.stderr)
	}
}

func TestOpen_aMangledLinkNeverReachesTheServer(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	l := link(t, run(t, f, options{stdin: "x"}, "send", "--server", f.srv.URL))
	before := f.callCount()
	key := keyOf(t, l)
	for name, bad := range map[string]string{
		"no key":      strings.SplitN(l, "#", 2)[0],
		"short key":   strings.SplitN(l, "#", 2)[0] + "#" + key[:40],
		"wrong path":  f.srv.URL + "/r/id1#" + key,
		"not a link":  "hello",
		"empty stdin": "",
	} {
		args := []string{"open", bad}
		if bad == "" {
			args = []string{"open", "-"}
		}
		r := run(t, f, options{}, args...)
		if r.code != 2 {
			t.Errorf("%s: open = %d, want 2", name, r.code)
		}
	}
	if f.callCount() != before || f.held() != 1 {
		t.Errorf("a mangled link made %d calls and the server holds %d, want none and 1", f.callCount()-before, f.held())
	}
}

func TestOpen_escapesControlCharactersOnATerminal(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	const text = "ok\x1b]0;title\x07 done\rover\nnext\tcol"
	l := link(t, run(t, f, options{stdin: text}, "send", "--server", f.srv.URL))
	r := run(t, f, options{terminal: true}, "open", l)
	if r.code != 0 {
		t.Fatalf("open = %d %s", r.code, r.stderr)
	}
	if strings.ContainsAny(r.stdout, "\x1b\x07\r") {
		t.Errorf("terminal output still holds control characters: %q", r.stdout)
	}
	if !strings.Contains(r.stdout, "\nnext\tcol") || !strings.Contains(r.stderr, "escapes") {
		t.Errorf("stdout %q stderr %q: newline and tab stay, and the person is told", r.stdout, r.stderr)
	}
}

func TestOpen_rawBytesWhenRedirected(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	const text = "a\x1b[0mb"
	l := link(t, run(t, f, options{stdin: text}, "send", "--server", f.srv.URL))
	if r := run(t, f, options{terminal: false}, "open", l); r.stdout != text {
		t.Errorf("redirected output = %q, want the exact text", r.stdout)
	}
}

func TestSend_limits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		stdin string
		args  []string
		max   int
		code  int
		want  string
	}{
		{"lifetime below the minimum", "x", []string{"--lifetime", "30s"}, 0, 1, "between"},
		{"lifetime above the maximum", "x", []string{"--lifetime", "8d"}, 0, 1, "between"},
		{"lifetime that is not a duration", "x", []string{"--lifetime", "soon"}, 0, 2, "--lifetime"},
		{"lifetime with fractions of a second", "x", []string{"--lifetime", "1500ms"}, 0, 2, "whole number"},
		{"empty input", "", nil, 0, 1, "nothing to send"},
		{"binary input", "a\xffb", nil, 0, 1, "--file"},
		{"too large for the server", strings.Repeat("a", 1000), nil, 600, 1, "larger"},
		{"padded to more than the server accepts", strings.Repeat("a", 300), nil, 400, 1, "at most 400"},
		{"stray argument", "x", []string{"extra"}, 0, 2, "no arguments"},
		{"name without file", "x", []string{"--name", "n"}, 0, 2, "--file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeServer(t)
			if tt.max != 0 {
				f.maxBytes = tt.max
			}
			r := run(t, f, options{stdin: tt.stdin}, append([]string{"send", "--server", f.srv.URL}, tt.args...)...)
			if r.code != tt.code || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("send = %d %q, want %d containing %q", r.code, r.stderr, tt.code, tt.want)
			}
			if r.stdout != "" || f.stores != 0 {
				t.Errorf("a refused send printed %q and stored %d", r.stdout, f.stores)
			}
		})
	}
}

func TestSend_lifetimeReachesTheServer(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	link(t, run(t, f, options{stdin: "x"}, "send", "--server", f.srv.URL, "--lifetime", "2h"))
	link(t, run(t, f, options{stdin: "x"}, "send", "--server", f.srv.URL, "--lifetime", "3d"))
	link(t, run(t, f, options{stdin: "x"}, "send", "--server", f.srv.URL))
	if fmt.Sprint(f.lifetimes) != "[7200 259200]" {
		t.Errorf("lifetimes = %v, want two explicit ones and none for the default", f.lifetimes)
	}
}

func TestSend_serverChoice(t *testing.T) {
	t.Parallel()
	flagServer := newFakeServer(t)
	envServer := newFakeServer(t)
	link(t, run(t, flagServer, options{stdin: "x", env: map[string]string{EnvServer: envServer.srv.URL}}, "send", "--server", flagServer.srv.URL))
	link(t, run(t, envServer, options{stdin: "x", env: map[string]string{EnvServer: envServer.srv.URL}}, "send"))
	if flagServer.stores != 1 || envServer.stores != 1 {
		t.Errorf("stores: flag server %d, environment server %d, want 1 each", flagServer.stores, envServer.stores)
	}
	if r := run(t, nil, options{stdin: "x"}, "send", "--server", "not a url"); r.code != 2 {
		t.Errorf("a bad server exited with %d, want 2", r.code)
	}
}

func TestSend_hintOnATerminal(t *testing.T) {
	t.Parallel()
	f := newFakeServer(t)
	var stderr bytes.Buffer
	env := Env{
		Stdin: strings.NewReader("x"), Stdout: &bytes.Buffer{}, Stderr: &stderr,
		Getenv: func(string) string { return "" }, HTTP: f.srv.Client(), StdinIsTerminal: true,
	}
	if code := Run(context.Background(), []string{"send", "--server", f.srv.URL}, env); code != 0 {
		t.Fatalf("send = %d %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Ctrl-D") {
		t.Errorf("stderr %q gives no hint on a terminal", stderr.String())
	}
}

func TestRun_commands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		code int
	}{
		{"no command", nil, 2},
		{"unknown command", []string{"share"}, 2},
		{"help", []string{"help"}, 0},
		{"help flag of a command", []string{"send", "-h"}, 0},
		{"version", []string{"version"}, 0},
		{"open without a link", []string{"open"}, 2},
		{"open with two links", []string{"open", "a", "b"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if r := run(t, nil, options{}, tt.args...); r.code != tt.code {
				t.Errorf("exit code = %d, want %d (%s)", r.code, tt.code, r.stderr)
			}
		})
	}
}

func TestSafeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"report.pdf", "report.pdf"},
		{"  spaced name.txt  ", "spaced name.txt"},
		{strings.Repeat("a", 200), strings.Repeat("a", maxNameRunes)},
		{strings.Repeat("ä", 200), strings.Repeat("ä", maxNameRunes)},
		{"com1", "_com1"},
		{"LPT9.log", "_LPT9.log"},
		{"console.txt", "console.txt"},
		{"...", "secret"},
		{"\x00", "_"},
		{"a/b\\c:d", "a_b_c_d"},
		{"report?.pdf", "report_.pdf"},
		{`<a>"b"|c*d.txt`, "_a__b__c_d.txt"},
		{lre + rlo, "secret"},
	}
	for _, tt := range tests {
		if got := safeName(tt.in); got != tt.want {
			t.Errorf("safeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeForTerminal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
		changed  bool
	}{
		{"plain ✓ text\n\tindented", "plain ✓ text\n\tindented", false},
		{"a\x1b[2Jb", `a\u{1b}[2Jb`, true},
		{"cr\rlf", `cr\rlf`, true},
		{"bell\x07", `bell\u{7}`, true},
		{rlo + "evil", `\u{202e}evil`, true},
		{"zero" + zwsp + "width", `zero\u{200b}width`, true},
	}
	for _, tt := range tests {
		got, changed := escapeForTerminal(tt.in)
		if got != tt.want || changed != tt.changed {
			t.Errorf("escapeForTerminal(%q) = %q, %v, want %q, %v", tt.in, got, changed, tt.want, tt.changed)
		}
	}
}

func TestParseLifetime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		wantSec int64
		wantErr bool
	}{
		{"90s", 90, false},
		{"30m", 1800, false},
		{"12h", 43200, false},
		{"7d", 604800, false},
		{"1h30m", 5400, false},
		{"0s", 0, true},
		{"-1h", 0, true},
		{"1.5d", 0, true},
		{"d", 0, true},
		{"", 0, true},
		{"500ms", 0, true},
	}
	for _, tt := range tests {
		got, err := parseLifetime(tt.in)
		if (err != nil) != tt.wantErr || (err == nil && int64(got.Seconds()) != tt.wantSec) {
			t.Errorf("parseLifetime(%q) = %v, %v, want %d seconds, error %v", tt.in, got, err, tt.wantSec, tt.wantErr)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	writeBytes(t, path, []byte(content))
}

func writeBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
