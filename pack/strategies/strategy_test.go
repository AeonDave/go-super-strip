package strategies

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// StripBuildIgnoreTag
// ---------------------------------------------------------------------------

func TestStripBuildIgnoreTag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "has_tag",
			src:  "//go:build ignore\n\npackage main\n",
			want: "package main\n",
		},
		{
			name: "no_tag",
			src:  "package main\n",
			want: "package main\n",
		},
		{
			name: "empty_string",
			src:  "",
			want: "",
		},
		{
			name: "tag_without_blank_line",
			src:  "//go:build ignore\npackage main\n",
			want: "//go:build ignore\npackage main\n",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := StripBuildIgnoreTag(tc.src)
			if got != tc.want {
				t.Errorf("StripBuildIgnoreTag(%q)\ngot  %q\nwant %q", tc.src, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

func TestResolve_SpecialValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		platform string
		wantName string
	}{
		{"", "windows", "base_exec"},
		{"off", "windows", "base_exec"},
		{"base_exec", "windows", "base_exec"},
		{"base_exec", "linux", "base_exec"},
		// case-insensitive and whitespace-trimmed
		{"  BASE_EXEC  ", "windows", "base_exec"},
		{"OFF", "linux", "base_exec"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"_"+tc.platform, func(t *testing.T) {
			t.Parallel()
			s, err := Resolve(tc.name, tc.platform)
			if err != nil {
				t.Fatalf("Resolve(%q, %q) unexpected error: %v", tc.name, tc.platform, err)
			}
			if s.Name() != tc.wantName {
				t.Errorf("got %q, want %q", s.Name(), tc.wantName)
			}
		})
	}
}

func TestResolve_Auto(t *testing.T) {
	t.Parallel()
	cases := []struct {
		platform string
		wantName string
	}{
		{"windows", "process_hollowing"},
		{"linux", "memfd"},
		{"AUTO_WINDOWS", "process_hollowing"}, // unrecognised platform → windows path
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.platform, func(t *testing.T) {
			t.Parallel()
			s, err := Resolve("auto", tc.platform)
			if err != nil {
				t.Fatalf("Resolve(auto, %q) unexpected error: %v", tc.platform, err)
			}
			if s.Name() != tc.wantName {
				t.Errorf("got %q, want %q", s.Name(), tc.wantName)
			}
		})
	}
}

func TestResolve_Explicit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		platform string
		wantName string
		wantErr  bool
	}{
		{"process_hollowing", "windows", "process_hollowing", false},
		{"self_injection", "windows", "self_injection", false},
		{"memfd", "linux", "memfd", false},
		// platform mismatch
		{"process_hollowing", "linux", "", true},
		{"self_injection", "linux", "", true},
		{"memfd", "windows", "", true},
		// unknown name
		{"xyzzy", "windows", "", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"_"+tc.platform, func(t *testing.T) {
			t.Parallel()
			s, err := Resolve(tc.name, tc.platform)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Resolve(%q, %q) expected error but got nil (strategy %q)", tc.name, tc.platform, s.Name())
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q, %q) unexpected error: %v", tc.name, tc.platform, err)
			}
			if s.Name() != tc.wantName {
				t.Errorf("got %q, want %q", s.Name(), tc.wantName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// List + Get
// ---------------------------------------------------------------------------

func TestList_Sorted(t *testing.T) {
	t.Parallel()
	names := List()
	if len(names) == 0 {
		t.Fatal("List() returned empty slice — no strategies registered")
	}
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("List() not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

func TestList_ContainsExpected(t *testing.T) {
	t.Parallel()
	want := []string{"base_exec", "memfd", "process_hollowing", "self_injection"}
	names := List()
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[n] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("List() missing expected strategy %q", w)
		}
	}
}

func TestGet(t *testing.T) {
	t.Parallel()
	t.Run("existing", func(t *testing.T) {
		t.Parallel()
		if s := Get("base_exec"); s == nil {
			t.Error("Get(\"base_exec\") returned nil")
		}
	})
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		if s := Get("nonexistent_strategy"); s != nil {
			t.Errorf("Get(nonexistent) returned %v, want nil", s.Name())
		}
	})
}

// ---------------------------------------------------------------------------
// RuntimeSource — verify the tag is stripped and source is non-empty
// ---------------------------------------------------------------------------

func TestRuntimeSource_NoBuildTag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		strategy string
		arch     string
	}{
		{"base_exec", "amd64"},
		{"base_exec", "386"},
		{"process_hollowing", "amd64"},
		{"process_hollowing", "386"},
		{"self_injection", "amd64"},
		{"self_injection", "386"},
		{"memfd", "amd64"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.strategy+"_"+tc.arch, func(t *testing.T) {
			t.Parallel()
			s := Get(tc.strategy)
			if s == nil {
				t.Fatalf("strategy %q not registered", tc.strategy)
			}
			src, err := s.RuntimeSource(tc.arch)
			if err != nil {
				t.Fatalf("RuntimeSource(%q) error: %v", tc.arch, err)
			}
			if src == "" {
				t.Fatal("RuntimeSource returned empty string")
			}
			if strings.HasPrefix(src, "//go:build ignore") {
				t.Error("RuntimeSource must return source without the //go:build ignore tag")
			}
			if !strings.Contains(src, "package main") {
				t.Error("RuntimeSource must contain 'package main'")
			}
			if !strings.Contains(src, "executeStrategy") {
				t.Error("RuntimeSource must declare the executeStrategy function")
			}
		})
	}
}

func TestRuntimeSource_UnsupportedArch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		strategy string
		arch     string
	}{
		{"process_hollowing", "arm64"},
		{"self_injection", "arm64"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.strategy+"_"+tc.arch, func(t *testing.T) {
			t.Parallel()
			s := Get(tc.strategy)
			if s == nil {
				t.Fatalf("strategy %q not registered", tc.strategy)
			}
			_, err := s.RuntimeSource(tc.arch)
			if err == nil {
				t.Fatalf("RuntimeSource(%q) expected error for unsupported arch", tc.arch)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SupportsArch
// ---------------------------------------------------------------------------

func TestSupportsArch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		strategy string
		arch     string
		want     bool
	}{
		{"base_exec", "amd64", true},
		{"base_exec", "arm64", true}, // any arch
		{"process_hollowing", "amd64", true},
		{"process_hollowing", "386", true},
		{"process_hollowing", "arm64", false},
		{"self_injection", "amd64", true},
		{"self_injection", "386", true},
		{"self_injection", "arm64", false},
		{"memfd", "amd64", true},
		{"memfd", "arm64", true}, // any arch
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.strategy+"_"+tc.arch, func(t *testing.T) {
			t.Parallel()
			s := Get(tc.strategy)
			if s == nil {
				t.Fatalf("strategy %q not registered", tc.strategy)
			}
			got := s.SupportsArch(tc.arch)
			if got != tc.want {
				t.Errorf("SupportsArch(%q) = %v, want %v", tc.arch, got, tc.want)
			}
		})
	}
}
