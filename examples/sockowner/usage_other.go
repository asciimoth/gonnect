//go:build !unix

package main

func unixUsage(_ string) string {
	return ""
}

func unixUsageNotes() string {
	return ""
}
