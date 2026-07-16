package main

func publicErrorMessage(code string) string {
	switch code {
	case "bad_request":
		return "request body is invalid"
	case "summary_failed":
		return "summary is temporarily unavailable"
	case "export_failed":
		return "export is temporarily unavailable"
	case "release_failed":
		return "account state release could not be completed"
	case "usage_invalid":
		return "usage payload is invalid"
	case "usage_store_failed":
		return "usage storage is temporarily unavailable"
	default:
		return "plugin operation failed"
	}
}
