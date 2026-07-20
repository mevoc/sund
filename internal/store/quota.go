package store

// Storage quota classes map a named tier to a ceiling, in bytes, on an account's
// stored (undelivered) message payloads. Quota is attributed to the queue
// owner's account — the recipient side the server knows — so senders stay
// pseudonymous without breaking accounting (PRD, Accounts).
const (
	quotaStandardBytes int64 = 64 << 20 // 64 MiB
	quotaLargeBytes    int64 = 1 << 30  // 1 GiB
)

var quotaClasses = map[string]int64{
	"standard": quotaStandardBytes,
	"large":    quotaLargeBytes,
}

// QuotaBytesForClass resolves a quota class name to its byte ceiling, falling
// back to the standard tier for an unknown name.
func QuotaBytesForClass(class string) int64 {
	if b, ok := quotaClasses[class]; ok {
		return b
	}
	return quotaStandardBytes
}
