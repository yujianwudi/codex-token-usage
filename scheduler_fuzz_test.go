package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const maxFuzzIdentityBytes = 4096

func FuzzCanonicalProviderAndAliases(f *testing.F) {
	f.Add("  CoDeX  ", "account", "account.json", "user@example.com", "nested/account.json")
	f.Add(" XAI ", "shared", "shared", "", "a.cpa.json")
	f.Add(" Custom-AI ", "", "", "", "")
	f.Add("\t\n", " A ", "a.JSON", "dir/a.json", "dir\\a.json")

	f.Fuzz(func(t *testing.T, provider, authID, authIndex, source, authFile string) {
		provider = boundedFuzzString(provider)
		authID = boundedFuzzString(authID)
		authIndex = boundedFuzzString(authIndex)
		source = boundedFuzzString(source)
		authFile = boundedFuzzString(authFile)

		canonical := canonicalProvider(provider)
		if want := strings.ToLower(strings.TrimSpace(provider)); canonical != want {
			t.Fatalf("canonicalProvider(%q) = %q, want %q", provider, canonical, want)
		}
		if canonicalProvider(canonical) != canonical {
			t.Fatalf("canonical provider is not idempotent: %q", canonical)
		}

		aliases := normalizeAccountAliases(authID, authIndex, source, authFile)
		assertCanonicalFuzzAliases(t, aliases)
		if again := normalizeAccountAliases(aliases...); !reflect.DeepEqual(again, aliases) {
			t.Fatalf("normalized aliases are not idempotent:\n first=%q\n again=%q", aliases, again)
		}

		strict := strictFileIdentityAliases(authFile, source)
		assertCanonicalFuzzAliases(t, strict)
		if again := strictFileIdentityAliases(strict...); !reflect.DeepEqual(again, strict) {
			t.Fatalf("strict file aliases are not idempotent:\n first=%q\n again=%q", strict, again)
		}
	})
}

func FuzzMixedSchedulerFiltering(f *testing.F) {
	f.Add([]byte{1, 2, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{2, 0, 0, 3, 3, 0, 4, 1, 5, 2, 6, 3})
	f.Add([]byte{3, 3, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	f.Add([]byte{0, 0, 0})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256 {
			raw = raw[:256]
		}
		cursor := fuzzByteCursor{raw: raw}
		req := schedulerPickRequest{Provider: fuzzRouteProvider(cursor.next())}
		declaredCount := int(cursor.next() % 5)
		for i := 0; i < declaredCount; i++ {
			req.Providers = append(req.Providers, fuzzDeclaredProvider(cursor.next()))
		}
		candidateCount := int(cursor.next() % 7)
		for i := 0; i < candidateCount; i++ {
			id := fmt.Sprintf("candidate-%d", i)
			if cursor.next()%5 == 0 {
				id = "shared-candidate"
			}
			req.Candidates = append(req.Candidates, schedulerAuthCandidate{
				ID:       id,
				Provider: fuzzCandidateProvider(cursor.next()),
				Status:   fuzzCandidateStatus(cursor.next()),
				Priority: int(int8(cursor.next())),
			})
		}

		quarantined := map[string]string{}
		quarantineMask := cursor.next()
		for bit, provider := range []string{providerCodex, providerXAI, "gemini", "custom-ai"} {
			if quarantineMask&(1<<bit) != 0 {
				quarantined[provider] = "fuzz quarantine"
			}
		}
		s := &store{}
		s.setAPIKeyPrivacyQuarantineSnapshot("scheduler-fuzz.db", quarantined)

		original := cloneSchedulerRequestForFuzz(req)
		prepared, err := s.prepareSchedulerRequest(req)
		if !reflect.DeepEqual(req, original) {
			t.Fatalf("prepareSchedulerRequest mutated its input:\n got=%#v\nwant=%#v", req, original)
		}
		if err != nil {
			return
		}
		if len(prepared.Candidates) == 0 {
			return
		}
		if prepared.filter == nil || len(prepared.filter.allowed) == 0 {
			t.Fatalf("prepared candidates have no route allowlist: %#v", prepared)
		}

		healthyCounts := make(map[schedulerFuzzCandidateKey]int, len(original.Candidates))
		healthyKeys := make(map[schedulerFuzzCandidateKey]struct{}, len(original.Candidates))
		for _, candidate := range original.Candidates {
			provider := normalizeSchedulerProvider(candidate.Provider)
			_, allowed := prepared.filter.allowed[provider]
			_, blocked := quarantined[provider]
			if provider != "" && allowed && schedulerCandidateActive(candidate) && !blocked {
				key := schedulerFuzzCandidateIdentity(candidate)
				healthyCounts[key]++
				healthyKeys[key] = struct{}{}
			}
		}
		for _, candidate := range prepared.Candidates {
			if candidate.Provider != normalizeSchedulerProvider(candidate.Provider) {
				t.Fatalf("prepared provider is not canonical: %q", candidate.Provider)
			}
			if _, allowed := prepared.filter.allowed[candidate.Provider]; !allowed {
				t.Fatalf("candidate outside route allowlist survived: %#v", candidate)
			}
			if !schedulerCandidateActive(candidate) {
				t.Fatalf("inactive candidate survived filtering: %#v", candidate)
			}
			if _, blocked := quarantined[candidate.Provider]; blocked {
				t.Fatalf("quarantined provider survived filtering: %#v", candidate)
			}
			key := schedulerFuzzCandidateIdentity(candidate)
			if healthyCounts[key] == 0 {
				t.Fatalf("prepared candidate is not an original healthy candidate: %#v", candidate)
			}
			healthyCounts[key]--
		}

		eligible := highestPrioritySchedulerCandidates(prepared.Candidates)
		picked := pickSchedulerCandidate("mixed-filter-fuzz", "", eligible)
		if _, ok := healthyKeys[schedulerFuzzCandidateIdentity(picked)]; !ok {
			t.Fatalf("selected candidate %#v does not belong to an allowed active input candidate", picked)
		}
	})
}

type schedulerFuzzCandidateKey struct {
	Provider string
	ID       string
	Status   string
	Priority int
}

func schedulerFuzzCandidateIdentity(candidate schedulerAuthCandidate) schedulerFuzzCandidateKey {
	return schedulerFuzzCandidateKey{
		Provider: normalizeSchedulerProvider(candidate.Provider),
		ID:       candidate.ID,
		Status:   normalizeSchedulerProvider(candidate.Status),
		Priority: candidate.Priority,
	}
}

func assertCanonicalFuzzAliases(t *testing.T, aliases []string) {
	t.Helper()
	seen := make(map[string]bool, len(aliases))
	for _, alias := range aliases {
		if alias == "" || alias != normalizeAccountAlias(alias) {
			t.Fatalf("non-canonical alias %q in %q", alias, aliases)
		}
		if seen[alias] {
			t.Fatalf("duplicate alias %q in %q", alias, aliases)
		}
		seen[alias] = true
	}
}

func boundedFuzzString(value string) string {
	if len(value) > maxFuzzIdentityBytes {
		return value[:maxFuzzIdentityBytes]
	}
	return value
}

type fuzzByteCursor struct {
	raw   []byte
	index int
}

func (c *fuzzByteCursor) next() byte {
	if len(c.raw) == 0 {
		return 0
	}
	value := c.raw[c.index%len(c.raw)]
	c.index++
	return value
}

func fuzzRouteProvider(value byte) string {
	providers := [...]string{"", "mixed", " MIXED ", "codex", " XAI ", "gemini", "custom-ai"}
	return providers[int(value)%len(providers)]
}

func fuzzDeclaredProvider(value byte) string {
	providers := [...]string{"", "mixed", " CODEX ", "xai", " XAI ", "gemini", "custom-ai", "codex"}
	return providers[int(value)%len(providers)]
}

func fuzzCandidateProvider(value byte) string {
	providers := [...]string{"", "codex", " CODEX ", "xai", " XAI ", "gemini", "custom-ai", "unknown-provider"}
	return providers[int(value)%len(providers)]
}

func fuzzCandidateStatus(value byte) string {
	statuses := [...]string{"", "active", " ACTIVE ", "disabled", "inactive", "error"}
	return statuses[int(value)%len(statuses)]
}

func cloneSchedulerRequestForFuzz(req schedulerPickRequest) schedulerPickRequest {
	cloned := req
	cloned.Providers = append([]string(nil), req.Providers...)
	cloned.Candidates = append([]schedulerAuthCandidate(nil), req.Candidates...)
	return cloned
}
