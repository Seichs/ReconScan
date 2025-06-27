#!/usr/bin/env python3
"""
ReconScan Comprehensive System Test

This script performs end-to-end testing of all major components:
1. Injection Point Discovery
2. Payload Crafting Engine
3. SQL Injection Detection
4. Response Analysis
5. AI Integration
6. Database Fingerprinting
7. Integration Testing

Author: ReconScan Security Framework
Version: 1.0.0
"""

import asyncio
import aiohttp
import time
import sys
import os
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.commands.scanning.shared.injection_discovery import (
    InjectionPointDiscovery, 
    InjectionPoint, 
    InjectionPointType, 
    ParameterType
)
from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_injection_scanner import (
    SQLInjectionScanner,
    DetectionTechnique,
    ScanMode,
    DatabaseType
)
from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_payload_crafting_engine import (
    PayloadCraftingEngine
)

class ComprehensiveSystemTest:
    """Comprehensive system test suite for ReconScan."""
    
    def __init__(self):
        """Initialize the test suite."""
        self.test_results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        
    async def run_all_tests(self):
        """Run all comprehensive tests."""
        print("🛡️  ReconScan Comprehensive System Test Suite")
        print("=" * 70)
        print()
        
        # Test 1: Injection Point Discovery
        await self.test_injection_discovery()
        
        # Test 2: Payload Crafting Engine
        await self.test_payload_crafting()
        
        # Test 3: SQL Injection Detection
        await self.test_sql_injection_detection()
        
        # Test 4: Integration Testing
        await self.test_integration()
        
        # Test 5: Performance Testing
        await self.test_performance()
        
        # Final summary
        self.print_final_summary()
    
    async def test_injection_discovery(self):
        """Test injection point discovery functionality."""
        print("🔍 Testing Injection Point Discovery")
        print("-" * 40)
        
        try:
            discovery = InjectionPointDiscovery()
            
            # Test 1: URL Parameter Discovery
            test_url = "http://example.com/search?q=test&category=books&page=1"
            discovery_result = await discovery.discover_injection_points(test_url)
            
            assert len(discovery_result.injection_points) >= 3, "Should find at least 3 parameters"
            assert any(point.name == 'q' for point in discovery_result.injection_points), "Should find 'q' parameter"
            assert any(point.name == 'category' for point in discovery_result.injection_points), "Should find 'category' parameter"
            assert any(point.name == 'page' for point in discovery_result.injection_points), "Should find 'page' parameter"
            
            # Test 2: Parameter Type Detection
            page_param = next((p for p in discovery_result.injection_points if p.name == 'page'), None)
            assert page_param is not None, "Page parameter should be found"
            assert page_param.parameter_type == ParameterType.NUMERIC, "Page parameter should be numeric"
            
            # Test 3: Priority Calculation
            high_priority_points = discovery_result.get_priority_points(min_priority=7)
            assert len(high_priority_points) > 0, "Should have high priority points"
            
            self.record_test_result("Injection Discovery", True, "All injection discovery tests passed")
            
        except Exception as e:
            self.record_test_result("Injection Discovery", False, f"Error: {e}")
    
    async def test_payload_crafting(self):
        """Test payload crafting engine functionality."""
        print("🎯 Testing Payload Crafting Engine")
        print("-" * 35)
        
        try:
            engine = PayloadCraftingEngine()
            
            # Test 1: Template Loading
            assert len(engine.templates) > 0, "Should have templates loaded"
            assert len(engine.templates) >= 5, "Should have templates for all techniques"
            
            # Test 2: Payload Generation
            test_injection_point = InjectionPoint(
                name="id",
                value="123",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.NUMERIC,
                url="http://example.com/product",
                method="GET"
            )
            
            payloads = engine.craft_payloads(test_injection_point, max_payloads=10)
            assert len(payloads) > 0, "Should generate payloads"
            assert len(payloads) <= 10, "Should respect max payloads limit"
            
            # Test 3: Technique-Specific Payloads
            from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_payload_crafting_engine import InjectionTechnique
            
            error_payloads = engine.craft_payloads(
                test_injection_point, 
                techniques=[InjectionTechnique.ERROR_BASED],
                max_payloads=5
            )
            assert len(error_payloads) > 0, "Should generate error-based payloads"
            
            # Test 4: Database-Specific Payloads
            from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_payload_crafting_engine import DatabaseType as CraftingDatabaseType
            
            mysql_payloads = engine.craft_payloads(
                test_injection_point,
                database_types=[CraftingDatabaseType.MYSQL],
                max_payloads=5
            )
            assert len(mysql_payloads) > 0, "Should generate MySQL-specific payloads"
            
            self.record_test_result("Payload Crafting", True, f"Generated {len(payloads)} payloads successfully")
            
        except Exception as e:
            self.record_test_result("Payload Crafting", False, f"Error: {e}")
    
    async def test_sql_injection_detection(self):
        """Test SQL injection detection functionality."""
        print("🔍 Testing SQL Injection Detection")
        print("-" * 35)
        
        try:
            # Create mock session
            session = aiohttp.ClientSession()
            scanner = SQLInjectionScanner(session)
            
            # Test 1: Scanner Initialization
            assert scanner is not None, "Scanner should initialize"
            assert scanner.payload_engine is not None, "Payload engine should be available"
            assert len(scanner.scan_configs) == 4, "Should have 4 scan modes"
            
            # Test 2: Technique Selection
            test_injection_point = InjectionPoint(
                name="search",
                value="test",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.STRING,
                url="http://example.com/search",
                method="GET"
            )
            
            config = scanner.scan_configs[ScanMode.THOROUGH]
            techniques = scanner._select_techniques(test_injection_point, config)
            assert len(techniques) > 0, "Should select techniques"
            assert DetectionTechnique.ERROR_BASED in techniques, "Should include error-based"
            
            # Test 3: Response Analysis
            # Error-based analysis
            error_result = scanner._analyze_error_based(
                "You have an error in your SQL syntax", 
                "' OR 1=1--", 
                {'vulnerable': False, 'confidence': 0.0, 'evidence': []}
            )
            assert error_result['vulnerable'] is True, "Should detect SQL error"
            assert error_result['confidence'] > 0, "Should have confidence > 0"
            
            # Time-based analysis
            time_result = scanner._analyze_time_based(
                5.2, 
                "' AND SLEEP(5)--", 
                {'vulnerable': False, 'confidence': 0.0, 'evidence': []}
            )
            assert time_result['vulnerable'] is True, "Should detect time delay"
            assert time_result['confidence'] > 0.5, "Should have high confidence for time delay"
            
            # Test 4: Database Fingerprinting
            print(f"         Debug: pattern count = {len(scanner.error_patterns)}")
            assert len(scanner.error_patterns) >= 5, "Should have patterns for multiple databases"
            
            print(f"         Debug: MySQL in patterns = {DatabaseType.MYSQL in scanner.error_patterns}")
            assert DatabaseType.MYSQL in scanner.error_patterns, "Should have MySQL patterns"
            
            print(f"         Debug: PostgreSQL in patterns = {DatabaseType.POSTGRESQL in scanner.error_patterns}")
            assert DatabaseType.POSTGRESQL in scanner.error_patterns, "Should have PostgreSQL patterns"
            
            # Check that MySQL patterns exist and contain SQL-related patterns
            mysql_patterns = scanner.error_patterns[DatabaseType.MYSQL]
            print(f"         Debug: MySQL pattern count = {len(mysql_patterns)}")
            assert len(mysql_patterns) > 0, "Should have MySQL patterns"
            
            has_sql_syntax = any("SQL syntax" in pattern for pattern in mysql_patterns)
            print(f"         Debug: Has SQL syntax = {has_sql_syntax}")
            assert has_sql_syntax, "Should have SQL syntax patterns"
            
            await session.close()
            self.record_test_result("SQL Injection Detection", True, "All detection tests passed")
            
        except Exception as e:
            self.record_test_result("SQL Injection Detection", False, f"Error: {e}")
    
    async def test_integration(self):
        """Test integration between all components."""
        print("🔗 Testing Component Integration")
        print("-" * 32)
        
        try:
            # Test 1: Discovery → Payload Generation
            discovery = InjectionPointDiscovery()
            engine = PayloadCraftingEngine()
            
            test_url = "http://example.com/login?username=admin&password=secret&remember=1"
            discovery_result = await discovery.discover_injection_points(test_url)
            
            assert len(discovery_result.injection_points) >= 3, "Should discover multiple parameters"
            
            # Generate payloads for discovered points
            total_payloads = 0
            for injection_point in discovery_result.injection_points:
                payloads = engine.craft_payloads(injection_point, max_payloads=5)
                total_payloads += len(payloads)
            
            assert total_payloads > 0, "Should generate payloads for discovered points"
            
            # Test 2: Payload Generation → Detection
            session = aiohttp.ClientSession()
            scanner = SQLInjectionScanner(session)
            
            # Test technique mapping
            assert scanner._map_to_crafting_technique(DetectionTechnique.ERROR_BASED) is not None
            assert scanner._map_parameter_type(ParameterType.NUMERIC) == 'numeric'
            assert scanner._map_parameter_type(ParameterType.STRING) == 'string'
            
            await session.close()
            
            self.record_test_result("Integration", True, f"Generated {total_payloads} payloads for {len(discovery_result.injection_points)} injection points")
            
        except Exception as e:
            self.record_test_result("Integration", False, f"Error: {e}")
    
    async def test_performance(self):
        """Test system performance."""
        print("⚡ Testing Performance")
        print("-" * 22)
        
        try:
            engine = PayloadCraftingEngine()
            
            # Test 1: Payload Generation Speed
            test_injection_point = InjectionPoint(
                name="id",
                value="123",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.NUMERIC,
                url="http://example.com/test",
                method="GET"
            )
            
            start_time = time.time()
            payloads = engine.craft_payloads(test_injection_point, max_payloads=100)
            end_time = time.time()
            
            generation_time = end_time - start_time
            payloads_per_second = len(payloads) / generation_time if generation_time > 0 else 0
            
            assert generation_time < 2.0, "Should generate 100 payloads in under 2 seconds"
            assert payloads_per_second > 50, "Should generate at least 50 payloads per second"
            
            # Test 2: Template Loading Performance
            start_time = time.time()
            new_engine = PayloadCraftingEngine()
            end_time = time.time()
            
            loading_time = end_time - start_time
            assert loading_time < 1.0, "Should load templates in under 1 second"
            
            self.record_test_result("Performance", True, f"Generated {len(payloads)} payloads at {payloads_per_second:.1f} payloads/sec")
            
        except Exception as e:
            self.record_test_result("Performance", False, f"Error: {e}")
    
    def record_test_result(self, test_name: str, passed: bool, details: str):
        """Record test result."""
        self.total_tests += 1
        if passed:
            self.passed_tests += 1
            status = "✅ PASSED"
        else:
            self.failed_tests += 1
            status = "❌ FAILED"
        
        self.test_results[test_name] = {
            'passed': passed,
            'details': details
        }
        
        print(f"   {status}: {test_name}")
        print(f"   Details: {details}")
        print()
    
    def print_final_summary(self):
        """Print final test summary."""
        print("📊 Final Test Summary")
        print("=" * 50)
        print()
        
        for test_name, result in self.test_results.items():
            status = "✅ PASSED" if result['passed'] else "❌ FAILED"
            print(f"{status}: {test_name}")
            if not result['passed']:
                print(f"   Error: {result['details']}")
        
        print()
        print(f"📈 Overall Results:")
        print(f"   Total Tests: {self.total_tests}")
        print(f"   Passed: {self.passed_tests}")
        print(f"   Failed: {self.failed_tests}")
        print(f"   Success Rate: {(self.passed_tests/self.total_tests*100):.1f}%")
        
        if self.failed_tests == 0:
            print()
            print("🎉 ALL TESTS PASSED! System is ready for Phase 4!")
            print("   → Advanced Exploitation & Comprehensive Reporting")
        else:
            print()
            print("⚠️  Some tests failed. Please review and fix issues before Phase 4.")
        
        print()
        print("🔧 Component Status:")
        print(f"   ✅ Injection Point Discovery: {'Ready' if self.test_results.get('Injection Discovery', {}).get('passed', False) else 'Needs Attention'}")
        print(f"   ✅ Payload Crafting Engine: {'Ready' if self.test_results.get('Payload Crafting', {}).get('passed', False) else 'Needs Attention'}")
        print(f"   ✅ SQL Injection Detection: {'Ready' if self.test_results.get('SQL Injection Detection', {}).get('passed', False) else 'Needs Attention'}")
        print(f"   ✅ Component Integration: {'Ready' if self.test_results.get('Integration', {}).get('passed', False) else 'Needs Attention'}")
        print(f"   ✅ Performance Optimization: {'Ready' if self.test_results.get('Performance', {}).get('passed', False) else 'Needs Attention'}")

async def main():
    """Main test execution."""
    test_suite = ComprehensiveSystemTest()
    await test_suite.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main()) 