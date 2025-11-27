#!/usr/bin/env python3
"""
Casbin Benchmark Results Formatter

This script parses Go benchmark output and formats it into readable tables
with performance analysis.
"""

import re
import sys
from typing import List, Dict, Tuple


class BenchmarkResult:
    """Represents a single benchmark result"""

    def __init__(self, name: str, iterations: int, ns_per_op: float,
                 bytes_per_op: int = 0, allocs_per_op: int = 0):
        self.name = name
        self.iterations = iterations
        self.ns_per_op = ns_per_op
        self.bytes_per_op = bytes_per_op
        self.allocs_per_op = allocs_per_op

    @property
    def ms_per_op(self) -> float:
        """Convert nanoseconds to milliseconds"""
        return self.ns_per_op / 1_000_000

    @property
    def mb_per_op(self) -> float:
        """Convert bytes to megabytes"""
        return self.bytes_per_op / (1024 * 1024)


def parse_benchmark_line(line: str) -> BenchmarkResult:
    """Parse a single benchmark output line"""
    # Example: BenchmarkEnforce_Scale/100-roles-1K-bindings-10    1000000    1234 ns/op    456 B/op    7 allocs/op
    pattern = r'(\S+)\s+(\d+)\s+([\d.]+)\s+ns/op(?:\s+([\d.]+)\s+B/op)?(?:\s+([\d.]+)\s+allocs/op)?'
    match = re.search(pattern, line)

    if not match:
        return None

    name = match.group(1)
    iterations = int(match.group(2))
    ns_per_op = float(match.group(3))
    bytes_per_op = int(float(match.group(4))) if match.group(4) else 0
    allocs_per_op = int(float(match.group(5))) if match.group(5) else 0

    return BenchmarkResult(name, iterations, ns_per_op, bytes_per_op, allocs_per_op)


def parse_benchmark_file(filename: str) -> List[BenchmarkResult]:
    """Parse all benchmarks from a file"""
    results = []

    try:
        with open(filename, 'r') as f:
            for line in f:
                if line.startswith('Benchmark'):
                    result = parse_benchmark_line(line)
                    if result:
                        results.append(result)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)

    return results


def group_results(results: List[BenchmarkResult]) -> Dict[str, List[BenchmarkResult]]:
    """Group results by benchmark category"""
    groups = {}

    for result in results:
        # Extract category from name (e.g., "BenchmarkEnforce_Scale/..." -> "Enforce_Scale")
        if '/' in result.name:
            category = result.name.split('/')[0].replace('Benchmark', '')
        else:
            category = result.name.replace('Benchmark', '')

        if category not in groups:
            groups[category] = []
        groups[category].append(result)

    return groups


def format_time(ns: float) -> str:
    """Format nanoseconds to human-readable time"""
    if ns < 1_000:
        return f"{ns:.2f} ns"
    elif ns < 1_000_000:
        return f"{ns/1_000:.2f} µs"
    elif ns < 1_000_000_000:
        return f"{ns/1_000_000:.2f} ms"
    else:
        return f"{ns/1_000_000_000:.2f} s"


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable size"""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val/1024:.2f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val/(1024*1024):.2f} MB"
    else:
        return f"{bytes_val/(1024*1024*1024):.2f} GB"


def print_table(results: List[BenchmarkResult], title: str):
    """Print results as a formatted table"""
    print(f"\n{'=' * 100}")
    print(f"{title}")
    print(f"{'=' * 100}")

    # Print header
    print(f"{'Benchmark':<50} {'Time/op':<15} {'Memory/op':<15} {'Allocs/op':<10}")
    print(f"{'-' * 100}")

    # Print rows
    for result in results:
        name = result.name.split('/')[-1] if '/' in result.name else result.name.replace('Benchmark', '')
        time_str = format_time(result.ns_per_op)
        mem_str = format_bytes(result.bytes_per_op) if result.bytes_per_op > 0 else "-"
        allocs_str = str(result.allocs_per_op) if result.allocs_per_op > 0 else "-"

        print(f"{name:<50} {time_str:<15} {mem_str:<15} {allocs_str:<10}")


def print_summary(results: List[BenchmarkResult]):
    """Print performance summary and analysis"""
    print(f"\n{'=' * 100}")
    print("Performance Summary")
    print(f"{'=' * 100}\n")

    # Find key metrics
    scale_results = [r for r in results if 'Scale' in r.name and '10K-roles-200K-bindings' in r.name]
    if scale_results:
        result = scale_results[0]
        print(f"Large Scale Performance (10K roles, 200K bindings):")
        print(f"  Authorization check: {format_time(result.ns_per_op)}")
        print(f"  Memory per op: {format_bytes(result.bytes_per_op)}")
        print(f"  Allocations per op: {result.allocs_per_op}")

        # Performance evaluation
        if result.ns_per_op < 10_000_000:  # < 10ms
            print(f"  ✓ EXCELLENT: Well under 10ms target")
        elif result.ns_per_op < 50_000_000:  # < 50ms
            print(f"  ✓ GOOD: Within acceptable range")
        else:
            print(f"  ⚠ NEEDS IMPROVEMENT: Above 50ms")
        print()

    # Custom function performance
    custom_results = [r for r in results if 'CustomFunctions' in r.name]
    if custom_results:
        print("Custom Function Performance:")
        for result in custom_results:
            func_name = result.name.split('/')[-1]
            print(f"  {func_name}: {format_time(result.ns_per_op)}")
        print()

    # Initialization performance
    init_results = [r for r in results if 'Initialization' in r.name and '10K-roles-200K-bindings' in r.name]
    if init_results:
        result = init_results[0]
        print(f"Engine Initialization (10K roles, 200K bindings):")
        print(f"  Time: {format_time(result.ns_per_op)}")
        print(f"  Memory: {format_bytes(result.bytes_per_op)}")
        print()

    # Parallel performance
    parallel_results = [r for r in results if 'Parallel' in r.name]
    if parallel_results:
        result = parallel_results[0]
        print(f"Parallel Execution:")
        print(f"  Time per op: {format_time(result.ns_per_op)}")
        print()


def print_comparison(results: List[BenchmarkResult]):
    """Print comparison with OPA benchmarks"""
    print(f"\n{'=' * 100}")
    print("Comparison with OPA (10K roles, 200K bindings)")
    print(f"{'=' * 100}\n")

    # Expected OPA performance (from benchmark_results.txt)
    opa_metrics = {
        "Initialization": 511_000_000,  # 511ms
        "Evaluate": 6_364_000_000,      # 6.364s for allow case
        "Memory": 728 * 1024 * 1024,    # 728MB
    }

    scale_results = [r for r in results if 'Scale' in r.name and '10K-roles-200K-bindings' in r.name]
    init_results = [r for r in results if 'Initialization' in r.name and '10K-roles-200K-bindings' in r.name]

    print(f"{'Metric':<30} {'OPA':<20} {'Casbin':<20} {'Improvement':<15}")
    print(f"{'-' * 100}")

    if init_results:
        casbin_init = init_results[0].ns_per_op
        improvement = opa_metrics["Initialization"] / casbin_init
        print(f"{'Initialization':<30} {format_time(opa_metrics['Initialization']):<20} "
              f"{format_time(casbin_init):<20} {improvement:.1f}x faster")

    if scale_results:
        casbin_eval = scale_results[0].ns_per_op
        improvement = opa_metrics["Evaluate"] / casbin_eval
        print(f"{'Authorization Check':<30} {format_time(opa_metrics['Evaluate']):<20} "
              f"{format_time(casbin_eval):<20} {improvement:.1f}x faster")

        casbin_mem = scale_results[0].bytes_per_op
        if casbin_mem > 0:
            improvement = opa_metrics["Memory"] / casbin_mem
            print(f"{'Memory per Operation':<30} {format_bytes(opa_metrics['Memory']):<20} "
                  f"{format_bytes(casbin_mem):<20} {improvement:.1f}x less")

    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 format_results.py <benchmark_results_file>")
        sys.exit(1)

    filename = sys.argv[1]
    results = parse_benchmark_file(filename)

    if not results:
        print("No benchmark results found in file")
        sys.exit(1)

    # Group and display results
    groups = group_results(results)

    for category, category_results in sorted(groups.items()):
        print_table(category_results, category)

    # Print summary and analysis
    print_summary(results)
    print_comparison(results)

    print(f"\n{'=' * 100}")
    print("Analysis Complete")
    print(f"{'=' * 100}\n")


if __name__ == "__main__":
    main()
