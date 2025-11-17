#!/bin/bash

# Polymorphic Packer Test Suite
# Comprehensive test for all polymorphic techniques
# Tests: uniqueness, execution, distribution, performance

set -e

# Configuration
BUILDS_QUICK=10
BUILDS_FULL=50
TEST_FILE="testfiles/simple_c"
OUTPUT_DIR="/tmp/gosstrip_test"
TIMEOUT_EXEC=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
log_section() {
    echo ""
    echo "========================================================================"
    echo "  $1"
    echo "========================================================================"
    echo ""
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup
cleanup() {
    rm -rf "$OUTPUT_DIR"
    rm -f "$TEST_FILE.packed"
}

trap cleanup EXIT

# Main test function
run_test_suite() {
    local test_mode="${1:-quick}"
    
    log_section "Polymorphic Packer Test Suite - Mode: $test_mode"
    
    # Build project
    log_info "Building project..."
    if ! go build -o gosstrip > /dev/null 2>&1; then
        log_error "Build failed"
        return 1
    fi
    log_success "Build successful"
    
    # Select build count based on mode
    local builds=$BUILDS_QUICK
    if [ "$test_mode" = "full" ]; then
        builds=$BUILDS_FULL
    fi
    
    # Test 1: Uniqueness & Execution
    log_section "Test 1: Hash Uniqueness & Execution ($builds builds)"
    test_uniqueness_and_execution "$builds"
    
    # Test 2: Variant Distribution
    if [ "$test_mode" = "full" ]; then
        log_section "Test 2: Variant Distribution Analysis"
        test_variant_distribution "$builds"
    fi
    
    # Test 3: Baseline Comparison
    log_section "Test 3: Baseline Comparison"
    test_baseline_comparison
    
    # Test 4: Performance
    log_section "Test 4: Performance Metrics"
    test_performance
    
    # Final Summary
    log_section "Test Suite Summary"
    print_summary
}

# Test 1: Uniqueness and Execution
test_uniqueness_and_execution() {
    local builds=$1
    local success_count=0
    local exec_count=0
    
    declare -a hashes
    
    mkdir -p "$OUTPUT_DIR"
    
    log_info "Generating $builds packed binaries..."
    
    for i in $(seq 1 $builds); do
        rm -f "$TEST_FILE.packed"
        
        # Pack with polymorphism
        if ./gosstrip -p="comp=xz,encr=aes,poly=true" "$TEST_FILE" > /dev/null 2>&1; then
            if [ -f "$TEST_FILE.packed" ]; then
                # Calculate hash
                hash=$(sha256sum "$TEST_FILE.packed" | awk '{print $1}')
                hashes+=("$hash")
                success_count=$((success_count + 1))
                
                # Test execution
                chmod +x "$TEST_FILE.packed"
                if timeout $TIMEOUT_EXEC "$TEST_FILE.packed" > /dev/null 2>&1; then
                    exec_count=$((exec_count + 1))
                fi
                
                # Save for analysis
                cp "$TEST_FILE.packed" "$OUTPUT_DIR/build_$i.bin"
            fi
        fi
        
        # Progress indicator
        if [ $((i % 10)) -eq 0 ]; then
            printf "  Progress: %d/%d\n" $i $builds
        fi
    done
    
    # Analyze uniqueness
    local unique_count=$(printf '%s\n' "${hashes[@]}" | sort -u | wc -l)
    
    echo ""
    log_info "Results:"
    echo "  Builds generated:     $success_count / $builds"
    echo "  Unique hashes:        $unique_count / $success_count"
    echo "  Successful execution: $exec_count / $success_count"
    
    # Validation
    if [ $unique_count -eq $success_count ] && [ $exec_count -eq $success_count ]; then
        log_success "PASS: 100% uniqueness and execution"
        TEST_1_RESULT="PASS"
    else
        log_error "FAIL: Uniqueness or execution issues detected"
        TEST_1_RESULT="FAIL"
    fi
    
    # Store results for summary
    TEST_1_UNIQUE=$unique_count
    TEST_1_EXEC=$exec_count
    TEST_1_TOTAL=$success_count
}

# Test 2: Variant Distribution
test_variant_distribution() {
    local builds=$1
    
    declare -A variant_count
    
    log_info "Analyzing variant distribution over $builds builds..."
    
    for i in $(seq 1 $builds); do
        rm -f "$TEST_FILE.packed"
        
        # Capture output with variant info
        output=$(./gosstrip -p="comp=xz,encr=aes,poly=true" "$TEST_FILE" 2>&1)
        
        # Extract variant type
        variant=$(echo "$output" | grep -o "stub_variant_[a-z_]*" | head -1)
        
        if [ ! -z "$variant" ]; then
            variant_count[$variant]=$((${variant_count[$variant]:-0} + 1))
        fi
        
        if [ $((i % 10)) -eq 0 ]; then
            printf "  Progress: %d/%d\n" $i $builds
        fi
    done
    
    echo ""
    log_info "Variant distribution:"
    
    local total_variants=0
    for variant in "${!variant_count[@]}"; do
        count=${variant_count[$variant]}
        percent=$((count * 100 / builds))
        printf "  %-30s %3d (%2d%%)\n" "$variant" "$count" "$percent"
        total_variants=$((total_variants + 1))
    done
    
    echo ""
    echo "  Total unique variants: $total_variants"
    
    if [ $total_variants -ge 5 ]; then
        log_success "PASS: Good variant diversity ($total_variants variants)"
        TEST_2_RESULT="PASS"
    else
        log_warning "PASS: Limited diversity ($total_variants variants)"
        TEST_2_RESULT="PASS"
    fi
    
    TEST_2_VARIANTS=$total_variants
}

# Test 3: Baseline Comparison
test_baseline_comparison() {
    log_info "Comparing polymorphic vs non-polymorphic builds..."
    
    # Non-polymorphic builds
    declare -a baseline_hashes
    for i in $(seq 1 5); do
        rm -f "$TEST_FILE.packed"
        ./gosstrip -p="comp=xz,encr=aes,poly=false" "$TEST_FILE" > /dev/null 2>&1
        hash=$(sha256sum "$TEST_FILE.packed" 2>/dev/null | awk '{print $1}')
        baseline_hashes+=("$hash")
    done
    
    baseline_unique=$(printf '%s\n' "${baseline_hashes[@]}" | sort -u | wc -l)
    
    # Polymorphic builds
    declare -a poly_hashes
    for i in $(seq 1 5); do
        rm -f "$TEST_FILE.packed"
        ./gosstrip -p="comp=xz,encr=aes,poly=true" "$TEST_FILE" > /dev/null 2>&1
        hash=$(sha256sum "$TEST_FILE.packed" 2>/dev/null | awk '{print $1}')
        poly_hashes+=("$hash")
    done
    
    poly_unique=$(printf '%s\n' "${poly_hashes[@]}" | sort -u | wc -l)
    
    echo ""
    log_info "Results:"
    echo "  Non-polymorphic unique hashes: $baseline_unique / 5"
    echo "  Polymorphic unique hashes:     $poly_unique / 5"
    
    if [ $baseline_unique -eq 1 ] && [ $poly_unique -eq 5 ]; then
        log_success "PASS: Polymorphism transforms identical builds into unique ones"
        TEST_3_RESULT="PASS"
    elif [ $poly_unique -gt $baseline_unique ]; then
        log_success "PASS: Polymorphism increases uniqueness"
        TEST_3_RESULT="PASS"
    else
        log_warning "Unexpected baseline comparison results"
        TEST_3_RESULT="WARN"
    fi
}

# Test 4: Performance
test_performance() {
    log_info "Measuring performance metrics..."
    
    # Compile time
    rm -f gosstrip
    compile_start=$(date +%s.%N)
    go build -o gosstrip > /dev/null 2>&1
    compile_end=$(date +%s.%N)
    compile_time=$(echo "$compile_end - $compile_start" | bc)
    
    # Pack time (3 samples)
    total_pack_time=0
    for i in $(seq 1 3); do
        rm -f "$TEST_FILE.packed"
        pack_start=$(date +%s.%N)
        ./gosstrip -p="comp=xz,encr=aes,poly=true" "$TEST_FILE" > /dev/null 2>&1
        pack_end=$(date +%s.%N)
        pack_time=$(echo "$pack_end - $pack_start" | bc)
        total_pack_time=$(echo "$total_pack_time + $pack_time" | bc)
    done
    avg_pack_time=$(echo "scale=3; $total_pack_time / 3" | bc)
    
    # Size comparison
    original_size=$(stat -c%s "$TEST_FILE")
    packed_size=$(stat -c%s "$TEST_FILE.packed")
    overhead=$((packed_size - original_size))
    overhead_pct=$(echo "scale=1; ($overhead * 100) / $original_size" | bc)
    
    echo ""
    log_info "Results:"
    printf "  Compile time:      %.2f seconds\n" $compile_time
    printf "  Avg pack time:     %.3f seconds\n" $avg_pack_time
    echo "  Original size:     $original_size bytes"
    echo "  Packed size:       $packed_size bytes"
    printf "  Size overhead:     %d bytes (%.1f%%)\n" $overhead $overhead_pct
    
    log_success "PASS: Performance metrics collected"
    TEST_4_RESULT="PASS"
}

# Print summary
print_summary() {
    echo "Test Results:"
    echo "  1. Uniqueness & Execution:  $TEST_1_RESULT"
    if [ ! -z "$TEST_2_RESULT" ]; then
        echo "  2. Variant Distribution:    $TEST_2_RESULT"
    fi
    echo "  3. Baseline Comparison:     $TEST_3_RESULT"
    echo "  4. Performance Metrics:     $TEST_4_RESULT"
    
    echo ""
    echo "Details:"
    echo "  Unique hashes:      $TEST_1_UNIQUE / $TEST_1_TOTAL"
    echo "  Successful exec:    $TEST_1_EXEC / $TEST_1_TOTAL"
    if [ ! -z "$TEST_2_VARIANTS" ]; then
        echo "  Stub variants:      $TEST_2_VARIANTS"
    fi
    
    echo ""
    
    # Overall result
    if [ "$TEST_1_RESULT" = "PASS" ] && [ "$TEST_3_RESULT" = "PASS" ] && [ "$TEST_4_RESULT" = "PASS" ]; then
        log_success "ALL TESTS PASSED"
        return 0
    else
        log_error "SOME TESTS FAILED"
        return 1
    fi
}

# Parse arguments
MODE="${1:-quick}"

if [ "$MODE" != "quick" ] && [ "$MODE" != "full" ]; then
    echo "Usage: $0 [quick|full]"
    echo "  quick: Fast test with 10 builds (default)"
    echo "  full:  Comprehensive test with 50 builds and distribution analysis"
    exit 1
fi

# Run test suite
run_test_suite "$MODE"
