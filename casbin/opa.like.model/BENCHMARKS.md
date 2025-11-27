# Casbin OPA-like Model Benchmarks

This directory contains a comprehensive benchmark suite for the Casbin authorization model that uses OPA-like patterns with hierarchical resources and environment-based conditions.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Model Characteristics](#model-characteristics)
- [Benchmark Suite](#benchmark-suite)
- [Test Data Generation](#test-data-generation)
- [Interpreting Results](#interpreting-results)
- [Performance Comparison](#performance-comparison)
- [Optimization Tips](#optimization-tips)
- [Continuous Benchmarking](#continuous-benchmarking)

## Overview

This benchmark suite evaluates the Casbin authorization model's performance across different scales and scenarios. It mirrors the OPA benchmark structure to enable direct comparison between Casbin and OPA implementations.

### Model Characteristics

The Casbin opa.like.model uses:

**Request format**: `grp, dom, act, ctx`
- `grp`: Group identifier (e.g., "group:devs")
- `dom`: Domain/resource path (e.g., "//openchoreo.orgs/acme/project/p1")
- `act`: Action (e.g., "component.create")
- `ctx`: Context JSON string (e.g., `{"environment":"development"}`)

**Policy format**: `grp, dom, role, eft, cond`
- `grp`: Group identifier
- `dom`: Resource path prefix
- `role`: Role name (e.g., "roles/developer.450")
- `eft`: Effect ("allow" or "deny")
- `cond`: Condition JSON (e.g., `{"allowedEnvironments":["development"]}`)

**Custom Functions**:
- `prefixMatch(reqDom, polDom)`: Hierarchical resource path matching
- `ctxAllowed(reqCtx, polCond)`: JSON-based environment condition validation

**Matcher Logic**: All conditions must match:
1. Resource path matches policy domain (prefix match)
2. Group matches policy group (exact match)
3. Action maps to policy role (role-to-action mapping)
4. Context satisfies policy conditions (environment check)

## Quick Start

### Running All Benchmarks

```bash
# Using the shell script (recommended)
./run_benchmarks.sh

# Or directly with go test
go test -bench=. -benchmem -benchtime=2s
```

### Running Specific Benchmarks

```bash
# Run only scale benchmarks
go test -bench=BenchmarkEnforce_Scale -benchmem

# Run only custom function benchmarks
go test -bench=BenchmarkCustomFunctions -benchmem

# Run with longer duration for more stable results
go test -bench=BenchmarkEnforce_Scale -benchmem -benchtime=10s
```

### Profiling

```bash
# CPU profiling
./run_benchmarks.sh --profile

# Or manually
go test -bench=BenchmarkEnforce_Scale/10K-roles-200K-bindings -cpuprofile=cpu.prof
go tool pprof cpu.prof

# Memory profiling
go test -bench=BenchmarkMemory -memprofile=mem.prof
go tool pprof mem.prof
```

### Formatting Results

```bash
# Run benchmarks and format output
./run_benchmarks.sh
python3 format_results.py benchmark_results.txt
```

## Benchmark Suite

### 1. Engine Initialization (`BenchmarkEngineInitialization`)

**Purpose**: Measures the cost of creating and initializing the Casbin enforcer, including policy loading and custom function registration.

**Test Scales**:
- 1K roles, 10K bindings
- 10K roles, 200K bindings

**What it measures**:
- Enforcer creation time
- Policy CSV loading and parsing
- Custom function registration overhead
- Initial policy indexing

**Performance Target**: <200ms for 10K roles / 200K bindings

### 2. Enforce Scale (`BenchmarkEnforce_Scale`)

**Purpose**: Tests authorization check latency at different scales to understand how performance scales with policy size.

**Test Scales**:
- 100 roles / 1K bindings (baseline)
- 100 roles / 100K bindings (stress test)
- 1K roles / 10K bindings (typical production)
- 10K roles / 200K bindings (large enterprise)

**What it measures**:
- Authorization decision time
- Policy lookup efficiency
- Matcher evaluation performance

**Performance Target**: <10ms for 10K roles / 200K bindings

### 3. Enforce Patterns (`BenchmarkEnforce_Patterns`)

**Purpose**: Tests different authorization scenarios at a fixed large scale (10K/200K) to understand pattern-specific performance characteristics.

**Patterns**:
- **allow-direct-group**: Group directly has policy binding
- **allow-inherited**: Permission inherited from parent resource (tests prefixMatch)
- **allow-with-condition**: Environment condition check (tests ctxAllowed)
- **deny-no-permission**: Fast-fail path when no permission exists
- **deny-explicit**: Explicit deny effect

**What it measures**:
- Best-case (direct match) vs worst-case (inherited) performance
- Conditional evaluation overhead
- Deny path performance

### 4. Enforce Hierarchy (`BenchmarkEnforce_Hierarchy`)

**Purpose**: Tests the impact of resource path depth on prefixMatch performance.

**Resource Levels**:
- **Org**: `//openchoreo.orgs/org001` (2 segments)
- **OU**: `//openchoreo.orgs/org001/ous/ou001` (4 segments)
- **Project**: `.../projects/proj0001` (6 segments)
- **Component**: `.../components/comp0001` (8 segments)

**What it measures**:
- prefixMatch performance with varying path depths
- String comparison overhead
- Whether hierarchy depth affects performance

**Expected**: Minimal impact (<5% variation), as prefixMatch is O(n) where n = path length

### 5. Enforce Principal Groups (`BenchmarkEnforce_PrincipalGroups`)

**Purpose**: Tests the impact of varying group identifiers (simulates different group contexts).

**Group Counts**: 0, 1, 5, 10, 20 groups

**What it measures**:
- Policy lookup performance with different groups
- Whether group identifier affects matching

**Note**: This model uses group-based authorization, so we test with different group identifiers rather than multiple groups per principal.

### 6. Enforce Parallel (`BenchmarkEnforce_Parallel`)

**Purpose**: Tests concurrent authorization performance to evaluate thread safety and scalability.

**Setup**: 1000 pre-generated varied scenarios, using `b.RunParallel()`

**What it measures**:
- Concurrent request handling
- Lock contention
- Scalability with CPU cores

**Expected**: Good scaling due to Casbin's read-lock design for thread safety

### 7. Memory Large Scale (`BenchmarkMemory_LargeScale`)

**Purpose**: Measures total memory footprint for large-scale enforcer creation.

**Scale**: 10K roles, 200K bindings

**What it measures**:
- Total memory allocation
- Policy storage overhead
- Index memory usage

**Performance Target**: <300MB for 10K roles / 200K bindings

### 8. Custom Functions (`BenchmarkCustomFunctions`)

**Purpose**: Isolates and measures custom function performance independently.

**Tests**:
- **prefixMatch-exact**: Same resource and policy domain
- **prefixMatch-inherited**: Deep resource path vs parent domain
- **ctxAllowed-no-condition**: Empty condition handling
- **ctxAllowed-env-match**: Environment validation with JSON parsing
- **ctxAllowed-env-no-match**: Failed environment check

**What it measures**:
- Native Go string operation performance
- JSON parsing overhead
- Function call overhead

**Why important**: These functions are called for every policy match candidate, so sub-millisecond performance is critical.

## Test Data Generation

### Role Distribution

Roles are distributed to simulate realistic organizational structures:

- **40% Viewer roles**: 3-5 permissions (read-only access)
- **40% Developer roles**: 6-10 permissions (read/write access)
- **15% Admin roles**: 11-20 permissions (management access)
- **5% Superadmin roles**: 20+ permissions (full access)

**Actions**: component, deployment, project, ou, org
**Verbs**: create, read, update, delete, deploy, view
**Format**: `action.verb` (e.g., `component.create`)

### Resource Hierarchy

Resources are distributed across a hierarchical structure:

- **10 organizations**: `//openchoreo.orgs/org{id}`
- **20 OUs per org**: `.../ous/ou{id}`
- **50 projects per OU**: `.../projects/proj{id}`
- **20 components per project**: `.../components/comp{id}`

Total possible resources: 10 × 20 × 50 × 20 = 200,000 components

### Policy Binding Distribution

Bindings are distributed across hierarchy levels:

- **1% at org level** (~2,000 bindings for 200K total)
- **10% at OU level** (~20,000 bindings)
- **30% at project level** (~60,000 bindings)
- **59% at component level** (~118,000 bindings)

### Condition Distribution

Policy conditions (environment restrictions):

- **70% no conditions**: `{}`
- **25% single environment**: `{"allowedEnvironments":["development"]}`
- **5% multi-environment**: `{"allowedEnvironments":["development","staging"]}`

### Effect Distribution

- **95% allow**: Normal access grants
- **5% deny**: Explicit denials for testing deny-overrides logic

### Group Distribution

- **2000 groups total**: `group:team-{id}`
- Randomly assigned to policies

## Interpreting Results

### Metrics Explained

**ns/op (nanoseconds per operation)**:
- The time taken for a single operation
- Lower is better
- 1,000,000 ns = 1 millisecond (ms)
- Target: <10,000,000 ns (<10ms) for authorization checks

**B/op (bytes per operation)**:
- Memory allocated per operation
- Lower is better
- 1,048,576 B = 1 megabyte (MB)

**allocs/op (allocations per operation)**:
- Number of memory allocations per operation
- Lower is better
- Fewer allocations reduce GC pressure

### Performance Targets

| Metric | Target | Production Ready |
|--------|--------|------------------|
| Authorization check (10K/200K) | <10ms | <50ms |
| Engine initialization (10K/200K) | <200ms | <1s |
| Memory footprint (10K/200K) | <300MB | <1GB |
| Custom functions | <1ms combined | <5ms |
| Parallel scaling | Near-linear | >50% efficiency |

### Example Output

```
BenchmarkEnforce_Scale/10K-roles-200K-bindings-10    1000000    1234567 ns/op    12345 B/op    123 allocs/op
```

**Reading**:
- Benchmark name: `BenchmarkEnforce_Scale/10K-roles-200K-bindings`
- Parallelism: `-10` (10 parallel executions)
- Iterations: `1000000` (ran 1 million times)
- Time: `1234567 ns/op` = ~1.23 ms per operation ✓ EXCELLENT
- Memory: `12345 B/op` = ~12 KB per operation ✓ GOOD
- Allocations: `123 allocs/op` ✓ ACCEPTABLE

## Performance Comparison

### Casbin vs OPA (Expected)

| Metric | OPA (10K/200K) | Casbin (Expected) | Improvement |
|--------|----------------|-------------------|-------------|
| Initialization | 511 ms | 150-200 ms | 2.5-3.4× faster |
| Authorization Check (allow) | 6,364 ms | 5-15 ms | 400-1200× faster |
| Authorization Check (deny) | 4,658 ms | 1-5 ms | 900-4600× faster |
| Memory | 728 MB | 200-300 MB | 2.4-3.6× less |
| prefixMatch | N/A | <0.1 ms | Native Go |
| ctxAllowed | N/A | <0.5 ms | Native Go + JSON |

### Why Casbin is Faster

**OPA's Approach**:
- Rego policy iterates through all 200K bindings for each authorization check
- Interpreted policy language with runtime overhead
- No native indexing of bindings

**Casbin's Approach**:
- Indexed policy lookups (O(log n) instead of O(n))
- Native Go code (compiled, not interpreted)
- Efficient hash-based policy matching
- Custom functions in native Go

**Key Insight**: The performance difference is most dramatic at large scales. At 100 roles / 1K bindings, both systems perform well. At 10K roles / 200K bindings, Casbin's indexed approach shows 100-1000× improvement.

## Optimization Tips

### Custom Function Optimization

**prefixMatch**:
- Uses native Go string operations (very fast)
- Keep resource paths reasonably short (<200 chars)
- Avoid deep nesting when possible (though performance impact is minimal)

**ctxAllowed**:
- JSON parsing is the main overhead
- Keep condition JSON simple and small
- Cache parsed conditions if calling frequently (not currently implemented)

### Policy Structure Optimization

1. **Minimize policy count**: Consolidate similar policies where possible
2. **Use broader resource scopes**: Grant at higher levels (org/OU) rather than individual components when appropriate
3. **Limit conditions**: Only use environment conditions when necessary (they add JSON parsing overhead)
4. **Balance deny rules**: Too many deny rules can slow down evaluation (Casbin must check all denies)

### General Performance Tips

1. **Reuse enforcer instances**: Creating an enforcer is expensive; reuse across requests
2. **Warm up**: First few calls may be slower due to Go runtime warmup
3. **Monitor memory**: Watch memory usage in production; adjust policy counts if needed
4. **Profile in production**: Use pprof to identify actual bottlenecks in your use case

### When to Scale

Consider sharding or caching if:
- Authorization checks consistently take >50ms
- Memory usage exceeds 1GB
- You have >1M policy bindings
- You need >10K authorization checks per second

## Continuous Benchmarking

### Detecting Performance Regressions

Use `benchstat` to compare benchmark runs:

```bash
# Run baseline benchmarks
go test -bench=. -benchmem > old.txt

# Make changes to code

# Run new benchmarks
go test -bench=. -benchmem > new.txt

# Compare results
benchstat old.txt new.txt
```

**Installing benchstat**:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
```

### CI/CD Integration

Add to your CI pipeline:

```yaml
# Example GitHub Actions workflow
- name: Run benchmarks
  run: |
    cd casbin/opa.like.model
    go test -bench=. -benchmem > benchmarks.txt

- name: Compare with baseline
  run: |
    benchstat baseline.txt benchmarks.txt
```

### Setting SLOs (Service Level Objectives)

Define clear performance objectives:

```yaml
slos:
  authorization_latency_p50: 5ms
  authorization_latency_p99: 20ms
  initialization_time: 200ms
  memory_usage: 300MB
```

### Monitoring in Production

Instrument your code to track:
- Authorization check latency (p50, p95, p99)
- Cache hit rates (if using caching)
- Policy reload time
- Memory usage over time

## Troubleshooting

### Benchmarks Taking Too Long

- Reduce `-benchtime` (default is adaptive, usually 1s)
- Run specific benchmarks instead of all
- Start with smaller scales (100-roles-1K-bindings)

### Inconsistent Results

- Run with `-benchtime=10s` for more stable results
- Ensure system is not under load
- Close other applications
- Run multiple times and average

### Out of Memory

- Reduce benchmark scale (try 1K roles instead of 10K)
- Increase available memory
- Check for memory leaks in custom code

## Additional Resources

- [Casbin Documentation](https://casbin.org/docs/overview)
- [Go Benchmark Documentation](https://pkg.go.dev/testing#hdr-Benchmarks)
- [OPA Benchmark Comparison](../opa/model2/BENCHMARKS.md)
- [Performance Profiling with pprof](https://go.dev/blog/pprof)

## Contributing

To add new benchmarks:

1. Add data generation functions to `bench_data_gen.go`
2. Add benchmark function to `bench_test.go`
3. Update this documentation
4. Run benchmarks and validate results
5. Compare with baseline using benchstat

## License

See repository LICENSE file.
