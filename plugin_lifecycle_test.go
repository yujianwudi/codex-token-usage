package main

import "testing"

func TestMaxPluginRequestLimitFitsAuthImportEnvelope(t *testing.T) {
	if maxPluginRequestBytes < 16<<20 {
		t.Fatalf("max plugin request bytes = %d, too small for an 8 MiB auth import envelope", maxPluginRequestBytes)
	}
}
