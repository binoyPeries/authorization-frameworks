#!/bin/bash

# Casbin OPA-like Model Benchmark Runner
# This script runs benchmarks with various configurations

set -e

BENCHMARK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BENCHMARK_DIR"

echo "=========================================="
echo "Casbin OPA-like Model Benchmarks"
echo "=========================================="
echo ""

# Default values
BENCHTIME="2s"
OUTPUT_FILE="benchmark_results.txt"
RUN_PROFILING=false
CPU_PROFILE="cpu.prof"
MEM_PROFILE="mem.prof"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --benchtime)
            BENCHTIME="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --profile)
            RUN_PROFILING=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --benchtime DURATION   Set benchmark time (default: 2s)"
            echo "  --output FILE          Set output file (default: benchmark_results.txt)"
            echo "  --profile              Enable CPU and memory profiling"
            echo "  --help                 Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                  # Run with defaults"
            echo "  $0 --benchtime 10s                  # Run longer benchmarks"
            echo "  $0 --profile                        # Run with profiling"
            echo "  $0 --output custom_results.txt      # Custom output file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if model.conf exists
if [ ! -f "model.conf" ]; then
    echo "Error: model.conf not found in current directory"
    exit 1
fi

echo "Configuration:"
echo "  Benchmark time: $BENCHTIME"
echo "  Output file: $OUTPUT_FILE"
echo "  Profiling: $RUN_PROFILING"
echo ""

# Run benchmarks
echo "Running benchmarks..."
echo ""

if [ "$RUN_PROFILING" = true ]; then
    echo "Running with CPU and memory profiling..."
    go test -bench=. -benchmem -benchtime="$BENCHTIME" \
        -cpuprofile="$CPU_PROFILE" \
        -memprofile="$MEM_PROFILE" \
        | tee "$OUTPUT_FILE"

    echo ""
    echo "=========================================="
    echo "Profiling Results"
    echo "=========================================="
    echo ""
    echo "CPU profile saved to: $CPU_PROFILE"
    echo "Memory profile saved to: $MEM_PROFILE"
    echo ""
    echo "To analyze CPU profile:"
    echo "  go tool pprof $CPU_PROFILE"
    echo "  (pprof) top10"
    echo "  (pprof) web"
    echo ""
    echo "To analyze memory profile:"
    echo "  go tool pprof $MEM_PROFILE"
    echo "  (pprof) top10"
    echo "  (pprof) list functionName"
else
    go test -bench=. -benchmem -benchtime="$BENCHTIME" | tee "$OUTPUT_FILE"
fi

echo ""
echo "=========================================="
echo "Benchmark Complete"
echo "=========================================="
echo ""
echo "Results saved to: $OUTPUT_FILE"
echo ""
echo "To format results with Python:"
echo "  python3 format_results.py $OUTPUT_FILE"
echo ""
echo "To compare with previous results:"
echo "  benchstat old_results.txt $OUTPUT_FILE"
echo ""
