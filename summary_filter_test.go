package main

import "testing"

func TestFilterCurrentConfiguredAccountsRemovesHistoryWhenAuthDirectoryIsEmpty(t *testing.T) {
	accounts := []accountRow{{AuthID: "historical-account"}}

	got := filterCurrentConfiguredAccounts(accounts, nil, true)
	if len(got) != 0 {
		t.Fatalf("expected no accounts for a readable empty auth directory, got %d", len(got))
	}
}

func TestFilterCurrentConfiguredAccountsKeepsHistoryWhenAuthDirectoryIsUnreadable(t *testing.T) {
	accounts := []accountRow{{AuthID: "historical-account"}}

	got := filterCurrentConfiguredAccounts(accounts, nil, false)
	if len(got) != 1 || got[0].AuthID != "historical-account" {
		t.Fatalf("expected historical accounts to be retained when the auth directory is unreadable, got %#v", got)
	}
}
