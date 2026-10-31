package connector_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/xcwds/valet/"

// Core code never imports a specific connector (RFC decision 7): outside
// internal/connector/<name>/, the only connector package anyone may import
// is internal/connector/builtin, the list valetd starts with. Tests may use
// the fake.
func TestCoreImportsNoSpecificConnector(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		inConnector := strings.HasPrefix(rel, "internal/connector/") && strings.Count(rel, "/") >= 3
		if inConnector {
			return nil // a connector's own package, or builtin
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			sub, ok := strings.CutPrefix(p, modulePath+"internal/connector/")
			if ok && sub != "builtin" {
				t.Errorf("%s imports %s: core code must not import a specific connector", rel, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
