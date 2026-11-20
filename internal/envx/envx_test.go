package envx

import (
	"slices"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	values, skipped := Clean(map[string]string{
		"DATABASE_URL":   "postgres://x",
		"bad-name":       "x",
		"PATH":           "/evil",
		"LD_PRELOAD":     "/evil.so",
		"GROW_SECRETS_X": "x",
		"BIG":            strings.Repeat("a", MaxValueBytes+1),
		"NUL":            "a\x00b",
		"_ok1":           "y",
	})
	if len(values) != 2 || values["DATABASE_URL"] != "postgres://x" || values["_ok1"] != "y" {
		t.Fatalf("values: %v", Names(values))
	}
	if len(skipped) != 6 {
		t.Fatalf("skipped: %+v", skipped)
	}
	for _, s := range skipped {
		if strings.Contains(s.Reason, "evil") || strings.Contains(s.Name, "aaaa") {
			t.Fatalf("skip leaks a value: %+v", s)
		}
	}
}

func TestMergeOverridesByDefault(t *testing.T) {
	base := []string{"A=1", "B=2", "GROW_SECRETS_SECRET_ID=s", "A=dup"}
	got := Merge(base, map[string]string{"B": "secret", "C": "3"}, MergeOptions{})
	want := []string{"A=1", "B=secret", "GROW_SECRETS_SECRET_ID=s", "C=3"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMergeKeepExistingAndStrip(t *testing.T) {
	base := []string{"B=2", "GROW_SECRETS_ROLE_ID=r", "GROW_SECRETS_SECRET_ID=s", "GROW_SECRETS_PATH=p"}
	got := Merge(base, map[string]string{"B": "secret"}, MergeOptions{KeepExisting: true, StripBootstrap: true})
	want := []string{"B=2", "GROW_SECRETS_PATH=p"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMissing(t *testing.T) {
	got := Missing([]string{"A=1", "B="}, []string{"A", "B", " C ", ""})
	if !slices.Equal(got, []string{"B", "C"}) {
		t.Fatalf("got %v", got)
	}
}

func TestHashChangesWithValues(t *testing.T) {
	a := Hash(map[string]string{"A": "1", "B": "2"})
	if a != Hash(map[string]string{"B": "2", "A": "1"}) {
		t.Fatal("hash depends on map order")
	}
	if a == Hash(map[string]string{"A": "1", "B": "3"}) {
		t.Fatal("hash ignores a value change")
	}
	if a == Hash(map[string]string{"A": "1B", "": "2"}) {
		t.Fatal("hash is ambiguous")
	}
	if len(a) != 16 {
		t.Fatalf("hash length %d", len(a))
	}
}

func TestSplitList(t *testing.T) {
	if got := SplitList("A, B,,C\nD"); !slices.Equal(got, []string{"A", "B", "C", "D"}) {
		t.Fatalf("got %v", got)
	}
}
