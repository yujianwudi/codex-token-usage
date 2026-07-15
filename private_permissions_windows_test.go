//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsurePrivatePathsApplyProtectedWindowsDACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateFile(file); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, file} {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("DACL inheritance is not protected for %q", path)
		}
		owner, _, err := descriptor.Owner()
		if err != nil {
			t.Fatal(err)
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		if owner == nil || !owner.Equals(user.User.Sid) {
			t.Fatalf("owner for %q is not the current user", path)
		}
	}
}
