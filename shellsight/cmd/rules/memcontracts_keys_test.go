package rules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMemContractsCarryProvenanceConfig(t *testing.T) {
	path := filepath.Join("..", "..", "kb", "rules", "mem-contracts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var mc struct {
		Java struct {
			RetransformWatchlist []string `json:"retransform_watchlist"`
		} `json:"java"`
		Dotnet struct {
			FrameworkPublicKeys []string `json:"framework_public_keys"`
		} `json:"dotnet"`
	}
	if err := json.Unmarshal(data, &mc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mc.Java.RetransformWatchlist) == 0 {
		t.Error("java.retransform_watchlist is empty")
	}
	if !containsStr(mc.Java.RetransformWatchlist, "org.apache.catalina.core.ApplicationFilterChain") {
		t.Error("watchlist missing ApplicationFilterChain")
	}
	if len(mc.Dotnet.FrameworkPublicKeys) == 0 {
		t.Error("dotnet.framework_public_keys is empty")
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestMemContractsCarryFamilyKeys asserts the shipped mem-contract seeds the family-fingerprint
// key constants (Godzilla MD5("key")[:16], Behinder MD5("rebeyond")[:16]) into both runtimes'
// string_needles, so the probes scan recovered bytes for them.
func TestMemContractsCarryFamilyKeys(t *testing.T) {
	path := filepath.Join("..", "..", "kb", "rules", "mem-contracts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shipped mem-contracts.json: %v", err)
	}
	var mc struct {
		Java struct {
			StringNeedles []string `json:"string_needles"`
		} `json:"java"`
		Dotnet struct {
			StringNeedles []string `json:"string_needles"`
		} `json:"dotnet"`
	}
	if err := json.Unmarshal(data, &mc); err != nil {
		t.Fatalf("parse mem-contracts.json: %v", err)
	}
	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	for _, k := range []string{"3c6e0b8a9c15224a", "e45e329feb5d925b"} {
		if !has(mc.Dotnet.StringNeedles, k) {
			t.Errorf("dotnet.string_needles missing family key %s", k)
		}
		if !has(mc.Java.StringNeedles, k) {
			t.Errorf("java.string_needles missing family key %s", k)
		}
	}
}
