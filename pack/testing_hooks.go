package pack

// compileStubFunc allows tests to override stub compilation to avoid invoking
// the external Go toolchain while still exercising the packing pipeline.
var compileStubFunc = CompileStub

// SetStubCompilerForTests swaps the stub compiler used by PackELF/PackPE.
// It returns a function that restores the previous compiler and should be
// deferred by callers. This is primarily intended for integration tests.
func SetStubCompilerForTests(fn func(*PackConfig, *PayloadMetadata, []byte) ([]byte, error)) func() {
	prev := compileStubFunc
	compileStubFunc = fn
	return func() {
		compileStubFunc = prev
	}
}
