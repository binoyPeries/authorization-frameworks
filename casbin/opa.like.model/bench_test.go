package main

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/casbin/casbin/v2"
)

// Note: prefixMatch and ctxAllowed functions are defined in demo.go

// getMemStats returns current memory statistics
func getMemStats() runtime.MemStats {
	runtime.GC() // Force garbage collection for accurate measurement
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// setupBenchmarkEnforcer creates an enforcer with specified number of roles and bindings
func setupBenchmarkEnforcer(b *testing.B, numRoles, numBindings int) *casbin.Enforcer {
	b.Helper()

	// Generate data
	roles := generateRoles(numRoles)
	policies := generatePolicies(numBindings, roles)
	roleDefs := generateRoleDefinitions(roles)

	// Create temp policy file
	tmpFile, err := os.CreateTemp("", "policy-*.csv")
	if err != nil {
		b.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	// Write policy CSV
	if err := writePolicyCSV(tmpFile.Name(), policies, roleDefs); err != nil {
		os.Remove(tmpFile.Name())
		b.Fatalf("Failed to write policy CSV: %v", err)
	}

	// Create enforcer
	enforcer, err := casbin.NewEnforcer("model.conf", tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		b.Fatalf("Failed to create enforcer: %v", err)
	}

	// Register custom functions
	enforcer.AddFunction("prefixMatch", func(args ...interface{}) (interface{}, error) {
		reqDom := args[0].(string)
		polDom := args[1].(string)
		return prefixMatch(reqDom, polDom), nil
	})
	enforcer.AddFunction("ctxAllowed", func(args ...interface{}) (interface{}, error) {
		reqCtx := args[0].(string)
		polCond := args[1].(string)
		return ctxAllowed(reqCtx, polCond), nil
	})

	// Clean up temp file after benchmark (deferred)
	b.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	return enforcer
}

// BenchmarkEngineInitialization measures the cost of creating and initializing the enforcer
func BenchmarkEngineInitialization(b *testing.B) {
	scales := []struct {
		name     string
		roles    int
		bindings int
	}{
		{"1K-roles-10K-bindings", 1000, 10000},
		{"10K-roles-200K-bindings", 10000, 200000},
	}

	for _, scale := range scales {
		b.Run(scale.name, func(b *testing.B) {
			// Pre-generate data outside the timer
			roles := generateRoles(scale.roles)
			policies := generatePolicies(scale.bindings, roles)
			roleDefs := generateRoleDefinitions(roles)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Create temp file
				tmpFile, err := os.CreateTemp("", "policy-*.csv")
				if err != nil {
					b.Fatalf("Failed to create temp file: %v", err)
				}
				tmpFile.Close()

				// Write policy CSV
				if err := writePolicyCSV(tmpFile.Name(), policies, roleDefs); err != nil {
					os.Remove(tmpFile.Name())
					b.Fatalf("Failed to write policy CSV: %v", err)
				}

				// Create enforcer
				enforcer, err := casbin.NewEnforcer("model.conf", tmpFile.Name())
				if err != nil {
					os.Remove(tmpFile.Name())
					b.Fatalf("Failed to create enforcer: %v", err)
				}

				// Register custom functions
				enforcer.AddFunction("prefixMatch", func(args ...interface{}) (interface{}, error) {
					reqDom := args[0].(string)
					polDom := args[1].(string)
					return prefixMatch(reqDom, polDom), nil
				})
				enforcer.AddFunction("ctxAllowed", func(args ...interface{}) (interface{}, error) {
					reqCtx := args[0].(string)
					polCond := args[1].(string)
					return ctxAllowed(reqCtx, polCond), nil
				})

				// Clean up
				os.Remove(tmpFile.Name())
			}
		})
	}
}

// BenchmarkEnforce_Scale tests authorization performance at different scales
func BenchmarkEnforce_Scale(b *testing.B) {
	scales := []struct {
		name     string
		roles    int
		bindings int
	}{
		{"1K-roles-100K-bindings", 1000, 100000},
	}

	for _, scale := range scales {
		b.Run(scale.name, func(b *testing.B) {
			enforcer := setupBenchmarkEnforcer(b, scale.roles, scale.bindings)
			scenario := generateTypicalScenario()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Test with each group (simulating checking all subject's groups)
				allowed := false
				for _, group := range scenario.Groups {
					result, err := enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
					if err != nil {
						b.Fatalf("Enforce failed: %v", err)
					}
					if result {
						allowed = true
						break // Short-circuit on first allow
					}
				}
				_ = allowed
			}
		})
	}
}

// BenchmarkEnforce_Patterns tests different authorization access patterns
func BenchmarkEnforce_Patterns(b *testing.B) {
	enforcer := setupBenchmarkEnforcer(b, 1000, 100000)

	patterns := []string{
		"allow-direct-group",
		"allow-inherited",
		"allow-with-condition",
		"deny-no-permission",
		"deny-explicit",
	}

	for _, pattern := range patterns {
		b.Run(pattern, func(b *testing.B) {
			scenario := generateScenarioForPattern(pattern)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				allowed := false
				for _, group := range scenario.Groups {
					result, err := enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
					if err != nil {
						b.Fatalf("Enforce failed: %v", err)
					}
					if result {
						allowed = true
						break
					}
				}
				_ = allowed
			}
		})
	}
}

// BenchmarkEnforce_Hierarchy tests the impact of resource hierarchy depth
func BenchmarkEnforce_Hierarchy(b *testing.B) {
	enforcer := setupBenchmarkEnforcer(b, 1000, 100000)

	depths := []struct {
		name         string
		resourcePath string
	}{
		{"org-level", "//openchoreo.orgs/org001"},
		{"ou-level", "//openchoreo.orgs/org001/ous/ou001"},
		{"project-level", "//openchoreo.orgs/org001/ous/ou001/projects/proj0001"},
		{"component-level", "//openchoreo.orgs/org001/ous/ou001/projects/proj0001/components/comp0001"},
	}

	for _, depth := range depths {
		b.Run(depth.name, func(b *testing.B) {
			scenario := generateScenarioForResource(depth.resourcePath)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				allowed := false
				for _, group := range scenario.Groups {
					result, err := enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
					if err != nil {
						b.Fatalf("Enforce failed: %v", err)
					}
					if result {
						allowed = true
						break
					}
				}
				_ = allowed
			}
		})
	}
}

// BenchmarkEnforce_PrincipalGroups tests the impact of different numbers of groups
func BenchmarkEnforce_PrincipalGroups(b *testing.B) {
	enforcer := setupBenchmarkEnforcer(b, 1000, 100000)

	groupCounts := []int{3, 5, 10, 20}

	for _, count := range groupCounts {
		b.Run(fmt.Sprintf("%d-groups", count), func(b *testing.B) {
			scenario := generateScenarioWithGroupCount(count)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				allowed := false
				for _, group := range scenario.Groups {
					result, err := enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
					if err != nil {
						b.Fatalf("Enforce failed: %v", err)
					}
					if result {
						allowed = true
						break
					}
				}
				_ = allowed
			}
		})
	}
}

// BenchmarkEnforce_Parallel tests concurrent authorization performance
func BenchmarkEnforce_Parallel(b *testing.B) {
	enforcer := setupBenchmarkEnforcer(b, 1000, 100000)
	scenarios := generateVariedScenarios(1000) // Pre-generate 1000 varied scenarios

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			scenario := scenarios[i%len(scenarios)]
			allowed := false
			for _, group := range scenario.Groups {
				result, err := enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
				if err != nil {
					b.Fatalf("Enforce failed: %v", err)
				}
				if result {
					allowed = true
					break
				}
			}
			_ = allowed
			i++
		}
	})
}

// BenchmarkMemory_LargeScale measures memory usage for large-scale enforcer creation
func BenchmarkMemory_LargeScale(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create enforcer from scratch each time to measure total memory
		roles := generateRoles(1000)
		policies := generatePolicies(100000, roles)
		roleDefs := generateRoleDefinitions(roles)

		// Create temp file
		tmpFile, err := os.CreateTemp("", "policy-*.csv")
		if err != nil {
			b.Fatalf("Failed to create temp file: %v", err)
		}
		tmpFile.Close()

		// Write policy CSV
		if err := writePolicyCSV(tmpFile.Name(), policies, roleDefs); err != nil {
			os.Remove(tmpFile.Name())
			b.Fatalf("Failed to write policy CSV: %v", err)
		}

		// Create enforcer
		enforcer, err := casbin.NewEnforcer("model.conf", tmpFile.Name())
		if err != nil {
			os.Remove(tmpFile.Name())
			b.Fatalf("Failed to create enforcer: %v", err)
		}

		// Register custom functions
		enforcer.AddFunction("prefixMatch", func(args ...interface{}) (interface{}, error) {
			reqDom := args[0].(string)
			polDom := args[1].(string)
			return prefixMatch(reqDom, polDom), nil
		})
		enforcer.AddFunction("ctxAllowed", func(args ...interface{}) (interface{}, error) {
			reqCtx := args[0].(string)
			polCond := args[1].(string)
			return ctxAllowed(reqCtx, polCond), nil
		})

		// Clean up
		os.Remove(tmpFile.Name())
	}
}

// BenchmarkCustomFunctions tests the performance of custom matching functions
func BenchmarkCustomFunctions(b *testing.B) {
	b.Run("prefixMatch-exact", func(b *testing.B) {
		reqDom := "//openchoreo.orgs/acme"
		polDom := "//openchoreo.orgs/acme"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prefixMatch(reqDom, polDom)
		}
	})

	b.Run("prefixMatch-inherited", func(b *testing.B) {
		reqDom := "//openchoreo.orgs/acme/ous/dev/projects/p1/components/c1"
		polDom := "//openchoreo.orgs/acme"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prefixMatch(reqDom, polDom)
		}
	})

	b.Run("ctxAllowed-no-condition", func(b *testing.B) {
		reqCtx := "{}"
		polCond := "{}"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ctxAllowed(reqCtx, polCond)
		}
	})

	b.Run("ctxAllowed-env-match", func(b *testing.B) {
		reqCtx := "{\"environment\":\"development\"}"
		polCond := "{\"allowedEnvironments\":[\"development\"]}"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ctxAllowed(reqCtx, polCond)
		}
	})

	b.Run("ctxAllowed-env-no-match", func(b *testing.B) {
		reqCtx := "{\"environment\":\"production\"}"
		polCond := "{\"allowedEnvironments\":[\"development\"]}"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ctxAllowed(reqCtx, polCond)
		}
	})
}

// BenchmarkMemory_EnforcerSize measures the in-memory size of the enforcer at different scales
func BenchmarkMemory_EnforcerSize(b *testing.B) {
	scales := []struct {
		name     string
		roles    int
		bindings int
	}{
		{"100-roles-1K-bindings", 100, 1000},
		{"1K-roles-10K-bindings", 1000, 10000},
		{"10K-roles-200K-bindings", 10000, 200000},
	}

	for _, scale := range scales {
		b.Run(scale.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Create enforcer
				enforcer := setupBenchmarkEnforcer(b, scale.roles, scale.bindings)

				// Perform some operations to ensure enforcer is fully loaded
				scenario := generateTypicalScenario()
				for _, group := range scenario.Groups {
					_, _ = enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
				}
			}
		})
	}
}

// BenchmarkMemory_EnforceOperations measures memory usage during authorization checks
func BenchmarkMemory_EnforceOperations(b *testing.B) {
	// Create enforcer once
	enforcer := setupBenchmarkEnforcer(b, 1000, 100000)

	b.Run("single-enforce", func(b *testing.B) {
		scenario := generateTypicalScenario()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, group := range scenario.Groups {
				_, _ = enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
			}
		}
	})

	b.Run("varied-enforces", func(b *testing.B) {
		scenarios := generateVariedScenarios(100)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			scenario := scenarios[i%len(scenarios)]
			for _, group := range scenario.Groups {
				_, _ = enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
			}
		}
	})
}

// BenchmarkRAM_Usage measures actual RAM/heap memory usage at different scales
func BenchmarkRAM_Usage(b *testing.B) {
	scales := []struct {
		name     string
		roles    int
		bindings int
	}{
		{"1K-roles-100K-bindings", 1000, 100000},
	}

	for _, scale := range scales {
		b.Run(scale.name, func(b *testing.B) {
			// Get baseline memory
			baseline := getMemStats()

			// Create enforcer
			enforcer := setupBenchmarkEnforcer(b, scale.roles, scale.bindings)

			// Get memory after creation
			afterCreate := getMemStats()

			// Perform some enforce operations
			scenario := generateTypicalScenario()
			for i := 0; i < 100; i++ {
				for _, group := range scenario.Groups {
					_, _ = enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
				}
			}

			// Get memory after operations
			afterOps := getMemStats()

			// Report memory usage
			b.ReportMetric(float64(afterCreate.HeapAlloc-baseline.HeapAlloc)/1024/1024, "MB-enforcer-heap")
			b.ReportMetric(float64(afterCreate.HeapInuse-baseline.HeapInuse)/1024/1024, "MB-enforcer-inuse")
			b.ReportMetric(float64(afterCreate.Sys-baseline.Sys)/1024/1024, "MB-enforcer-sys")
			b.ReportMetric(float64(afterOps.HeapAlloc-baseline.HeapAlloc)/1024/1024, "MB-with-ops-heap")

			// Print detailed stats
			b.Logf("\n=== RAM Usage for %s ===", scale.name)
			b.Logf("Baseline Heap: %s", formatBytes(baseline.HeapAlloc))
			b.Logf("After Enforcer Creation:")
			b.Logf("  Heap Allocated: %s (+%s)", formatBytes(afterCreate.HeapAlloc), formatBytes(afterCreate.HeapAlloc-baseline.HeapAlloc))
			b.Logf("  Heap In-Use: %s (+%s)", formatBytes(afterCreate.HeapInuse), formatBytes(afterCreate.HeapInuse-baseline.HeapInuse))
			b.Logf("  System Memory: %s (+%s)", formatBytes(afterCreate.Sys), formatBytes(afterCreate.Sys-baseline.Sys))
			b.Logf("After 100 Operations:")
			b.Logf("  Heap Allocated: %s (+%s from baseline)", formatBytes(afterOps.HeapAlloc), formatBytes(afterOps.HeapAlloc-baseline.HeapAlloc))
			b.Logf("  Heap In-Use: %s (+%s from baseline)", formatBytes(afterOps.HeapInuse), formatBytes(afterOps.HeapInuse-baseline.HeapInuse))
			b.Logf("  System Memory: %s (+%s from baseline)", formatBytes(afterOps.Sys), formatBytes(afterOps.Sys-baseline.Sys))
			b.Logf("  Total Objects: %d", afterOps.HeapObjects)
		})
	}
}

// BenchmarkRAM_Peak measures peak memory usage during heavy operations
func BenchmarkRAM_Peak(b *testing.B) {
	b.Run("1K-roles-100K-bindings", func(b *testing.B) {
		baseline := getMemStats()
		b.Logf("Baseline Memory: %s heap, %s system", formatBytes(baseline.HeapAlloc), formatBytes(baseline.Sys))

		// Create large enforcer
		enforcer := setupBenchmarkEnforcer(b, 1000, 100000)
		afterCreate := getMemStats()

		b.Logf("\nAfter Enforcer Creation:")
		b.Logf("  Heap Allocated: %s", formatBytes(afterCreate.HeapAlloc))
		b.Logf("  Heap In-Use: %s", formatBytes(afterCreate.HeapInuse))
		b.Logf("  System Memory: %s", formatBytes(afterCreate.Sys))
		b.Logf("  Increase from baseline: %s", formatBytes(afterCreate.HeapAlloc-baseline.HeapAlloc))

		// Run many concurrent operations to measure peak
		scenarios := generateVariedScenarios(1000)
		var maxHeap uint64

		for i := 0; i < 10000; i++ {
			scenario := scenarios[i%len(scenarios)]
			for _, group := range scenario.Groups {
				_, _ = enforcer.Enforce(group, scenario.Domain, scenario.Action, scenario.Context)
			}

			if i%1000 == 0 {
				m := getMemStats()
				if m.HeapAlloc > maxHeap {
					maxHeap = m.HeapAlloc
				}
			}
		}

		finalMem := getMemStats()
		b.Logf("\nAfter 10,000 Operations:")
		b.Logf("  Final Heap: %s", formatBytes(finalMem.HeapAlloc))
		b.Logf("  Peak Heap: %s", formatBytes(maxHeap))
		b.Logf("  System Memory: %s", formatBytes(finalMem.Sys))
		b.Logf("  Total Allocations: %d", finalMem.Mallocs)
		b.Logf("  Total Frees: %d", finalMem.Frees)
		b.Logf("  GC Runs: %d", finalMem.NumGC)

		b.ReportMetric(float64(afterCreate.HeapAlloc-baseline.HeapAlloc)/1024/1024, "MB-init")
		b.ReportMetric(float64(maxHeap-baseline.HeapAlloc)/1024/1024, "MB-peak")
		b.ReportMetric(float64(finalMem.Sys)/1024/1024, "MB-sys-total")
	})
}
