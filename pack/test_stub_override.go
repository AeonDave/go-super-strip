package pack

import "os"

func init() {
	prefix := os.Getenv("GOSSTRIP_TEST_STUB")
	if prefix == "" {
		return
	}
	compileStubFunc = func(_ *PackConfig, _ *PayloadMetadata, payload []byte) ([]byte, error) {
		return append([]byte(prefix), payload...), nil
	}
}
