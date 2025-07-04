package common

type CommonFileInfo struct {
	FileSize      int64
	IsPacked      bool
	HasOverlay    bool
	OverlayOffset int64
	OverlaySize   int64
	VersionInfo   map[string]string
}

type CommonSectionInfo struct {
	Entropy      float64
	MD5Hash      string
	SHA1Hash     string
	SHA256Hash   string
	IsExecutable bool
	IsReadable   bool
	IsWritable   bool
}

type ParseMode int

type ParseResult struct {
	Mode     ParseMode
	Success  bool
	Reason   string
	Warnings []string
}

const (
	PERM_READ    = 0x4
	PERM_WRITE   = 0x2
	PERM_EXECUTE = 0x1
)
