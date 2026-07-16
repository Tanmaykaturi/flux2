//go:build !windows

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
	"path/filepath"
	"strings"
	"syscall"
)

// allowedEnvPrefixes is the explicit set of environment variable prefixes
// forwarded to the plugin. This intentionally excludes loader-level variables
// (e.g. LD_PRELOAD, LD_LIBRARY_PATH) that could be used to inject code.
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
}

// filteredEnv returns a copy of os.Environ containing only variables whose
// names match allowedEnvPrefixes, preventing LD_PRELOAD-style injection.
func filteredEnv() []string {
	raw := os.Environ()
	filtered := make([]string, 0, len(raw))
	for _, kv := range raw {
		for _, prefix := range allowedEnvPrefixes {
			if strings.HasPrefix(kv, prefix) {
				filtered = append(filtered, kv)
				break
			}
		}
	}
	return filtered
}

// Exec replaces the current process with the plugin binary.
// This is what kubectl does — no signal forwarding or exit code propagation needed.
func Exec(path string, args []string) error {
	// Resolve to an absolute, lexically clean path to prevent path traversal
	// (e.g. directory entries containing "..") from reaching syscall.Exec.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("plugin exec: resolving path %q: %w", path, err)
	}
	absPath = filepath.Clean(absPath)

	// Restrict execution to the directory that holds the current binary so that
	// only co-located, trusted plugin binaries can be exec'd.
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("plugin exec: resolving current executable: %w", err)
	}
	pluginDir := filepath.Dir(filepath.Clean(selfPath))
	if !strings.HasPrefix(absPath, pluginDir+string(filepath.Separator)) {
		return fmt.Errorf("plugin exec: %q is outside the allowed plugin directory %q", absPath, pluginDir)
	}

	// Confirm the resolved target is a regular file before exec-ing it.
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("plugin exec: stat %q: %w", absPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin exec: %q is not a regular file", absPath)
	}

	// Verify the resolved binary has execute permission for the current process.
	// This guards against exec-ing a file that is readable but not executable,
	// and ensures the path has been fully validated before reaching syscall.Exec.
	if err := syscall.Access(absPath, syscall.X_OK); err != nil {
		return fmt.Errorf("plugin exec: %q is not executable: %w", absPath, err)
	}

	// Validate every argument: null bytes terminate C strings and can be used
	// to smuggle unexpected content past Go-level checks.
	for i, arg := range args {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("plugin exec: argument %d contains a null byte", i)
		}
	}

	// Pass only a safe, allow-listed subset of the environment to prevent
	// loader-level variable injection (e.g. LD_PRELOAD, LD_LIBRARY_PATH).
	return syscall.Exec(absPath, append([]string{absPath}, args...), filteredEnv())
}
