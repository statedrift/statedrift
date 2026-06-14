package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/statedrift/statedrift/internal/config"
)

// fsFixture builds a temp tree and returns its root:
//
//	<root>/a.txt          regular, "hello"
//	<root>/link           symlink -> a.txt
//	<root>/subdir/        dir
//	<root>/subdir/b.txt   regular, "world"
func fsFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "subdir", "b.txt"), []byte("world"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	return root
}

func fsCollect(t *testing.T, fsCfg config.Filesystem) *FilesystemTree {
	t.Helper()
	tree, err := collectFilesystem(&config.Config{Filesystem: fsCfg})
	if err != nil {
		t.Fatalf("collectFilesystem: %v", err)
	}
	return tree
}

func findEntry(tree *FilesystemTree, path string) (FileEntry, bool) {
	for _, e := range tree.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return FileEntry{}, false
}

func TestCollectFilesystemBasic(t *testing.T) {
	root := fsFixture(t)
	tree := fsCollect(t, config.Filesystem{Roots: []string{root}})

	// root dir + a.txt + link + subdir + subdir/b.txt = 5 entries.
	if tree.Files != 5 || len(tree.Entries) != 5 {
		t.Fatalf("Files=%d len=%d, want 5", tree.Files, len(tree.Entries))
	}
	if tree.Truncated {
		t.Error("tree should not be truncated")
	}
	if len(tree.RootHash) != 64 {
		t.Errorf("RootHash = %q, want 64 hex chars", tree.RootHash)
	}

	a, ok := findEntry(tree, filepath.Join(root, "a.txt"))
	if !ok {
		t.Fatal("a.txt missing from tree")
	}
	if a.Mode[0] != '-' {
		t.Errorf("a.txt mode = %q, want a regular file", a.Mode)
	}
	if a.SHA256 == "" {
		t.Error("a.txt should be hashed")
	}
	if a.Size != 5 {
		t.Errorf("a.txt size = %d, want 5", a.Size)
	}

	sub, ok := findEntry(tree, filepath.Join(root, "subdir"))
	if !ok {
		t.Fatal("subdir missing")
	}
	if sub.SHA256 != "" {
		t.Error("directory should not be hashed")
	}
	if sub.Size != 0 {
		t.Errorf("directory size = %d, want 0", sub.Size)
	}
	if sub.Mode[0] != 'd' {
		t.Errorf("subdir mode = %q, want a directory", sub.Mode)
	}

	link, ok := findEntry(tree, filepath.Join(root, "link"))
	if !ok {
		t.Fatal("symlink missing")
	}
	if link.Target != "a.txt" {
		t.Errorf("symlink target = %q, want a.txt", link.Target)
	}
	if link.SHA256 != "" {
		t.Error("symlink should not be hashed")
	}
}

func TestCollectFilesystemDeterministicRootHash(t *testing.T) {
	root := fsFixture(t)
	h1 := fsCollect(t, config.Filesystem{Roots: []string{root}}).RootHash
	h2 := fsCollect(t, config.Filesystem{Roots: []string{root}}).RootHash
	if h1 != h2 {
		t.Errorf("RootHash not deterministic: %q vs %q", h1, h2)
	}
	// Change one byte of content → the root hash must move.
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("HELLO"), 0644); err != nil {
		t.Fatal(err)
	}
	h3 := fsCollect(t, config.Filesystem{Roots: []string{root}}).RootHash
	if h3 == h1 {
		t.Error("content change must change the RootHash")
	}
}

func TestCollectFilesystemExcludes(t *testing.T) {
	root := fsFixture(t)
	tree := fsCollect(t, config.Filesystem{
		Roots:    []string{root},
		Excludes: []string{filepath.Join(root, "subdir")},
	})
	if _, ok := findEntry(tree, filepath.Join(root, "subdir")); ok {
		t.Error("excluded subdir should be absent")
	}
	if _, ok := findEntry(tree, filepath.Join(root, "subdir", "b.txt")); ok {
		t.Error("excluded subdir's children should be absent (SkipDir)")
	}
	if _, ok := findEntry(tree, filepath.Join(root, "a.txt")); !ok {
		t.Error("non-excluded a.txt should still be present")
	}
}

func TestCollectFilesystemMaxFilesTruncates(t *testing.T) {
	root := fsFixture(t)
	tree := fsCollect(t, config.Filesystem{Roots: []string{root}, MaxFiles: 2})
	if !tree.Truncated {
		t.Error("expected Truncated when cap is hit")
	}
	if len(tree.Entries) != 2 {
		t.Errorf("len = %d, want 2 (capped)", len(tree.Entries))
	}
	// Lexical walk: root dir first, then a.txt.
	if tree.Entries[0].Path != root || tree.Entries[1].Path != filepath.Join(root, "a.txt") {
		t.Errorf("truncation order not stable: %q, %q", tree.Entries[0].Path, tree.Entries[1].Path)
	}
}

func TestCollectFilesystemMaxFileSizeSkipsHash(t *testing.T) {
	root := fsFixture(t)
	// a.txt is 5 bytes; cap at 4 → recorded but not hashed.
	tree := fsCollect(t, config.Filesystem{Roots: []string{root}, MaxFileSize: 4})
	a, ok := findEntry(tree, filepath.Join(root, "a.txt"))
	if !ok {
		t.Fatal("a.txt missing")
	}
	if a.SHA256 != "" {
		t.Error("oversized file should not be hashed")
	}
	if a.Size != 5 {
		t.Errorf("oversized file size = %d, want 5 (still recorded)", a.Size)
	}
}

func TestCollectFilesystemDefaultRoots(t *testing.T) {
	// Empty Roots → default ["/etc"]. We don't assert /etc contents (host
	// dependent); just that the default is applied to tree.Roots. MaxFiles:1
	// keeps the walk from hashing all of /etc.
	tree := fsCollect(t, config.Filesystem{MaxFiles: 1})
	if len(tree.Roots) != 1 || tree.Roots[0] != "/etc" {
		t.Errorf("default roots = %v, want [/etc]", tree.Roots)
	}
}

func TestMerkleRootEmpty(t *testing.T) {
	if h := merkleRoot(nil); h != "" {
		t.Errorf("empty tree hash = %q, want empty", h)
	}
}
