package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fuzz targets for backup files, which come from outside: an uploaded file
// on the restore page, or one fetched from an SFTP server.

// backupTar builds an unencrypted backup with one file entry.
func backupTar(t testing.TB, name string, typ byte, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(n string, ty byte, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: ty, Mode: 0o600, Size: int64(len(b)), ModTime: time.Unix(0, 0)}); err != nil {
			t.Skip() // a name tar cannot write is no backup anyone can make
		}
		_, _ = tw.Write(b)
	}
	add(manifestName, tar.TypeReg, []byte(`{"format":1,"product":"RMMZit","server_version":"0.13.4","files":[]}`))
	add(databaseName, tar.TypeReg, []byte("rows"))
	add(name, typ, data)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// A restore writes files only inside the data directory, and only into
// the parts a backup may hold - whatever names the archive carries.
func FuzzRestoreEntryName(f *testing.F) {
	for _, s := range []string{"files/secret.key", "files/tls/agent.key", "files/library/a/b.ps1", "files/../x", "files/tls/../../x",
		"/etc/passwd", "files//tls/x", "files/tls\\..\\x", "files/logs/server.log", "files/./tls/x", "files/tls/", "files/library/../secret.key"} {
		f.Add(s, byte(tar.TypeReg))
	}
	f.Add("files/tls/link", byte(tar.TypeSymlink))
	f.Add("files/tls", byte(tar.TypeDir))
	f.Fuzz(func(t *testing.T, name string, typ byte) {
		raw := backupTar(t, name, typ, []byte("DATA"))
		root := t.TempDir()
		dataDir := filepath.Join(root, "data")
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		drain := func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }
		_, err := Restore(context.Background(), bytes.NewReader(raw), "", dataDir, drain)
		// Nothing may appear next to the data directory.
		if es, _ := os.ReadDir(root); len(es) != 1 {
			t.Fatalf("restore of %q wrote outside the data directory: %v", name, es)
		}
		_ = filepath.WalkDir(dataDir, func(p string, d os.DirEntry, _ error) error {
			if p == dataDir || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dataDir, p)
			if err != nil {
				t.Fatalf("failed restore of %q left %s", name, rel)
			}
			if !d.Type().IsRegular() || !safeRel(filepath.ToSlash(rel)) {
				t.Fatalf("restore of %q wrote %s (%v)", name, rel, d.Type())
			}
			return nil
		})
	})
}

// Arbitrary bytes as a backup file: never a panic, never a manifest from a
// file that is no backup.
func FuzzInspect(f *testing.F) {
	f.Add(backupTar(f, "files/secret.key", tar.TypeReg, []byte("K")))
	f.Add([]byte(encMagic + strings.Repeat("s", 24)))
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	f.Add([]byte("not a backup"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bytes.HasPrefix(b, []byte(encMagic)) {
			return // the passphrase path is fuzzed by FuzzDecReader (scrypt is too slow here)
		}
		m, err := Inspect(bytes.NewReader(b), "")
		if err == nil && (m == nil || m.Format != 1) {
			t.Fatalf("manifest %+v without error", m)
		}
	})
}

// The decryption of chunks, after the key is derived: damaged, cut or
// re-ordered chunks give an error, never a panic or a huge allocation.
func FuzzDecReader(f *testing.F) {
	key := bytes.Repeat([]byte{7}, 32)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	var prefix [8]byte
	seal := func(i uint32, last bool, plain []byte) []byte {
		var n [12]byte
		copy(n[:8], prefix[:])
		binary.BigEndian.PutUint32(n[8:], i)
		ad := []byte{0}
		if last {
			ad[0] = 1
		}
		s := aead.Seal(nil, n[:], plain, ad)
		out := binary.BigEndian.AppendUint32(nil, uint32(len(s))) // #nosec G115 -- small test chunk
		return append(out, s...)
	}
	f.Add(seal(0, true, []byte("hello")))
	f.Add(append(seal(0, false, []byte("a")), seal(1, true, []byte("b"))...))
	f.Add(seal(1, true, []byte("wrong number")))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := &decReader{r: bytes.NewReader(b), aead: aead, prefix: prefix}
		_, _ = io.Copy(io.Discard, io.LimitReader(d, 16<<20))
	})
}

// Names that pass safeRel stay inside one of DataFiles.
func FuzzSafeRel(f *testing.F) {
	for _, s := range []string{"tls/a", "../tls", "tls/../..", "secret.key", "library/x/../../y", "", ".", "tls\\x", "/tls"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		if !safeRel(rel) {
			return
		}
		dir := t.TempDir()
		got, err := filepath.Rel(dir, filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || got == ".." || strings.HasPrefix(got, ".."+string(filepath.Separator)) {
			t.Fatalf("safeRel(%q) leaves the data directory (%s)", rel, got)
		}
		top, _, _ := strings.Cut(rel, "/")
		ok := false
		for _, d := range DataFiles {
			ok = ok || top == d
		}
		if !ok {
			t.Fatalf("safeRel(%q) is outside DataFiles", rel)
		}
	})
}

// Answers of the SFTP server the backups go to (a server the console does
// not control): directory listings and status messages.
func FuzzParseNames(f *testing.F) {
	entry := func(name string, flags uint32) []byte {
		b := appendString(nil, name)
		b = appendString(b, "-rw------- 1 u u 0 "+name)
		b = binary.BigEndian.AppendUint32(b, flags)
		if flags&0x1 != 0 {
			b = append(b, make([]byte, 8)...)
		}
		return b
	}
	one := binary.BigEndian.AppendUint32(nil, 2)
	one = append(one, entry("rmmzit-backup-1.rzb", 1)...)
	one = append(one, entry("..", 0)...)
	f.Add(one)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(append(binary.BigEndian.AppendUint32(nil, 1), append(entry("x", 0x80000000), 0xff, 0xff, 0xff, 0xff)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		names, err := parseNames(b)
		if err != nil {
			return
		}
		total := 0
		for _, n := range names {
			if n == "." || n == ".." {
				t.Fatal("dot entry kept")
			}
			total += 12 + len(n)
		}
		if 4+total > len(b) {
			t.Fatalf("names longer than the answer")
		}
		_ = statusErr("op", b)
	})
}
