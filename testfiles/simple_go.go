package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	fmt.Println("=== Simple Go Test Executable ===")
	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("Arch: %s\n", runtime.GOARCH)
	fmt.Printf("Current time: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
	} else {
		fmt.Printf("Executable path: %s\n", exePath)

		// Calculate file hash
		if hash, err := calculateFileHash(exePath); err == nil {
			fmt.Printf("File SHA256: %s\n", hash)
		}
	}

	// Test HTTP client
	fmt.Println("\n=== HTTP Test ===")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://httpbin.org/user-agent")
	if err != nil {
		fmt.Printf("HTTP request failed: %v\n", err)
	} else {
		fmt.Printf("HTTP status: %s\n", resp.Status)
		_ = resp.Body.Close()
	}

	// Test file operations
	fmt.Println("\n=== File Operations Test ===")
	testFile := filepath.Join(os.TempDir(), "gotest_temp.txt")
	content := "Hello from Go test executable!"

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		fmt.Printf("Failed to write file: %v\n", err)
	} else {
		fmt.Printf("Created temp file: %s\n", testFile)

		if data, err := os.ReadFile(testFile); err == nil {
			fmt.Printf("File content: %s\n", string(data))
		}

		_ = os.Remove(testFile)
		fmt.Println("Temp file removed")
	}

	fmt.Println("\n=== Test completed successfully! ===")
}

func calculateFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
