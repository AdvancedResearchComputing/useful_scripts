package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveTargetAcceptsARealFilesetDir(t *testing.T) {
	setup(t)
	got, err := resolveTarget("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(projectsRoot, "arcadm") {
		t.Fatalf("got %s", got)
	}
}

func TestResolveTargetRefusals(t *testing.T) {
	setup(t)
	_ = os.WriteFile(filepath.Join(projectsRoot, "notadir"), nil, 0o600)
	_ = os.Symlink(filepath.Join(projectsRoot, "arcadm"), filepath.Join(projectsRoot, "alias"))

	for name, fileset := range map[string]string{
		"missing":     "nosuch",
		"regularfile": "notadir",
		"symlink":     "alias",
		"pathshaped":  "../etc",
		"empty":       "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveTarget(fileset); err == nil {
				t.Fatalf("%s: resolved %q, must refuse", name, fileset)
			}
		})
	}
}

func TestRepairArgvShape(t *testing.T) {
	argv := repairArgv("/gpfs/fs1/projects/arcadm", "arcadm")
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"/gpfs/fs1/projects/arcadm",
		"-xdev",
		"! -type l",
		chmodBin + " g+rwXs {} +",
		chownBin + " :arc.arcadm {} +",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %s", want, joined)
		}
	}
	if argv[0] != findBin {
		t.Fatalf("argv[0] = %s, want %s", argv[0], findBin)
	}
	// No uid filter: the authority a token attests is over the project root.
	if strings.Contains(joined, "-uid") {
		t.Fatal("argv carries a -uid filter")
	}
}

func TestShellWordsQuotesWhatAShellWouldEat(t *testing.T) {
	s := shellWords([]string{"find", "!", "{}", "+", "a b", "plain"})
	for _, want := range []string{"'!'", "'{}'", "'a b'", " plain"} {
		if !strings.Contains(s, want) {
			t.Fatalf("shellWords %q missing %q", s, want)
		}
	}
}
