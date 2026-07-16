//go:build windows

/*
Copyright 2026 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// allowedEnvPrefixes is the explicit set of environment variable prefixes
// forwarded to the plugin. This intentionally excludes variables that could
// be used to hijack process behaviour (e.g. ComSpec, PATHEXT, TEMP/TMP
// substitution attacks).
var allowedEnvPrefixes = []string{
	"HOME=",
	"USER=",
	"LOGNAME=",
	"PATH=",
	"TERM=",
	"LANG=",
	"LC_",
	"XDG_",
	"KUBECONFIG=",
	"FLUX_",
	"NO_COLOR=",
	"HTTPS_PROXY=",
	"HTTP_PROXY=",
	"NO_PROXY=",
	"https_proxy=",
	"http_proxy=",
	"no_proxy=",
	// Windows-specific variables required for normal process operation.
	"USERPROFILE=",
	"APPDATA=",
	"LOCALAPPDATA=",
	"SYSTEMROOT=",
	"WINDIR=",
	"PROGRAMFILES=",
	"PROGRAMFILES(X86)=",
}

// filteredEnv returns a copy of os.Environ containing only variables whose
// names match allowedEnvPrefixes, preventing environment-variable-based
// injection attacks.
func filteredEnv() []string {
	raw := os.Environ()
	filtered := make([]string, 0, len(raw))
	for _, kv := range raw {
		upper := strings.ToUpper(kv)
		for _, prefix := range allowedEnvPrefixes {
			if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
				filtered = append(filtered, kv)
				break
			}
		}
	}
	return filtered
}

// Exec runs the plugin as a child process with full I/O passthrough.
// Matches kubectl's Windows fallback pattern.
func Exec(path string, args []string) error {
	// Resolve to an absolute, lexically clean path to prevent path traversal
	// (e.g. directory entries containing "..") from reaching exec.Command.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("plugin exec: resolving path %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)

	// Restrict execution to the directory that holds the current binary so
	// that only co-located, trusted plugin binaries can be executed.
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("plugin exec: resolving current executable: %w", err)
	}
	pluginDir := filepath.Dir(filepath.Clean(selfPath))
	if !strings.HasPrefix(absPath, pluginDir+string(filepath.Separator)) {
		return fmt.Errorf("plugin exec: %q is outside the allowed plugin directory %q", absPath, pluginDir)
	}

	// Confirm the resolved target is a regular file before executing it.
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("plugin exec: stat %q: %w", absPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin exec: %q is not a regular file", absPath)
	}

	// Validate every argument: null bytes terminate C strings and can be used
	// to smuggle unexpected content past Go-level checks.
	for i, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("plugin exec: argument %d contains a null byte", i)
		}
	}

	// Resolve the binary through the OS path-lookup mechanism as a final
	// check that the file is accessible and executable. Because absPath is
	// already absolute, LookPath simply verifies OS-level accessibility
	// without performing any additional PATH search.
	//
	// Security: resolvedPath is safe to pass to exec.Command because it has
	// been through a full validation chain above:
	//   1. Converted to an absolute, lexically clean path (filepath.Abs +
	//      filepath.Clean).
	//   2. Restricted to the trusted plugin directory co-located with the
	//      current binary.
	//   3. Confirmed to be a regular file via os.Stat.
	//   4. Every argument was checked for null bytes.
	//   5. exec.LookPath verified OS-level accessibility.
	// No unverified user input can reach this call site.
	resolvedPath, err := exec.LookPath(absPath)
	if err != nil {
		return fmt.Errorf("plugin exec: binary not found or not executable %q: %w", absPath, err)
	}
	cmd := exec.Command(resolvedPath, args...) // nosemgrep: dangerous-exec-command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = filteredEnv()
	err = cmd.Run()
	if err == nil {
		os.Exit(0)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}
	return err
}
