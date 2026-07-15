package main

import "reflect"

func truncateSummaryResponse(data map[string]any, limit int) {
	if data == nil || limit <= 0 {
		return
	}
	data["requested_limit"] = limit
	switch info := data["precompute"].(type) {
	case summaryPrecomputeInfo:
		info.Limit = limit
		data["precompute"] = info
	case map[string]any:
		updated := make(map[string]any, len(info)+1)
		for key, value := range info {
			updated[key] = value
		}
		updated["limit"] = limit
		data["precompute"] = updated
	}
	for _, key := range []string{
		"accounts",
		"xai_accounts",
		"providers",
		"key_summaries",
		"models",
		"provider_models",
		"xai_models",
	} {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		slice := reflect.ValueOf(value)
		if slice.Kind() != reflect.Slice || slice.Len() <= limit {
			continue
		}
		data[key] = slice.Slice(0, limit).Interface()
	}
}
