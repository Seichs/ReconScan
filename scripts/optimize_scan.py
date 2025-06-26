#!/usr/bin/env python3
"""
ReconScan Performance Optimization Script

Helps optimize scan performance by testing different configurations
and providing recommendations for better vulnerability detection.
"""

import sys
import os
import time
import asyncio
import aiohttp

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from scanner.commands.scan import ScanCommand
from scanner.config_loader import get_system_config

class ScanOptimizer:
    """Performance optimizer for ReconScan vulnerability detection."""
    
    def __init__(self):
        self.config = get_system_config()
        
    def test_network_performance(self, target_url="https://httpbin.org/get"):
        """Test network performance to recommend optimal timeout settings."""
        print("🔍 Testing network performance...")
        
        async def test_connection():
            timeouts = [5, 10, 15, 20, 30]
            results = {}
            
            for timeout in timeouts:
                try:
                    start_time = time.time()
                    timeout_config = aiohttp.ClientTimeout(total=timeout)
                    
                    async with aiohttp.ClientSession(timeout=timeout_config) as session:
                        async with session.get(target_url) as response:
                            await response.text()
                            response_time = time.time() - start_time
                            results[timeout] = {
                                'success': True,
                                'response_time': response_time,
                                'status': response.status
                            }
                            print(f"  ✓ Timeout {timeout}s: {response_time:.2f}s response time")
                except Exception as e:
                    results[timeout] = {
                        'success': False,
                        'error': str(e)
                    }
                    print(f"  ✗ Timeout {timeout}s: Failed - {str(e)}")
            
            return results
        
        results = asyncio.run(test_connection())
        
        # Recommend optimal timeout
        successful_tests = {k: v for k, v in results.items() if v.get('success')}
        if successful_tests:
            avg_response_time = sum(v['response_time'] for v in successful_tests.values()) / len(successful_tests)
            recommended_timeout = max(15, int(avg_response_time * 3))  # 3x average response time, minimum 15s
            
            print(f"\n📊 Network Performance Analysis:")
            print(f"  Average response time: {avg_response_time:.2f}s")
            print(f"  Recommended timeout: {recommended_timeout}s")
            
            return recommended_timeout
        else:
            print("\n❌ All network tests failed. Check your internet connection.")
            return 30  # Default fallback
    
    def analyze_current_config(self):
        """Analyze current configuration and provide recommendations."""
        print("\n🔧 Analyzing current configuration...")
        
        # Get current settings
        network_config = self.config.get('defaults', {}).get('network', {})
        scanning_config = self.config.get('defaults', {}).get('scanning', {})
        payload_config = self.config.get('payload_defaults', {})
        
        current_timeout = network_config.get('timeout', 10)
        current_threads = scanning_config.get('threads', 5)
        current_delay = scanning_config.get('delay', 0.5)
        
        print(f"  Current timeout: {current_timeout}s")
        print(f"  Current threads: {current_threads}")
        print(f"  Current delay: {current_delay}s")
        
        # SQL injection settings
        sql_config = payload_config.get('sql_injection', {})
        sql_filtering = sql_config.get('false_positive_filtering', True)
        sql_level = sql_config.get('default_level', 'basic')
        
        print(f"  SQL injection level: {sql_level}")
        print(f"  AI filtering enabled: {sql_filtering}")
        
        # Provide recommendations
        print(f"\n💡 Recommendations for better vulnerability detection:")
        
        if current_timeout < 20:
            print(f"  🔹 Increase timeout to 20-30s to prevent timeouts on slower connections")
            
        if current_threads > 3:
            print(f"  🔹 Reduce threads to 2-3 to prevent rate limiting and improve stability")
            
        if current_delay < 1.0:
            print(f"  🔹 Increase delay to 1.0-1.5s to be more polite to target servers")
            
        if sql_filtering:
            print(f"  🔹 Consider disabling AI filtering (false_positive_filtering: false) for more thorough detection")
            
        if sql_level != 'advanced':
            print(f"  🔹 Use 'advanced' payload level for comprehensive SQL injection testing")
    
    def test_scan_performance(self, target_url):
        """Test scan performance with current configuration."""
        print(f"\n🚀 Testing scan performance against: {target_url}")
        
        scan_cmd = ScanCommand()
        
        # Test with current config
        print("  Testing with current configuration...")
        start_time = time.time()
        
        try:
            result = scan_cmd.execute(f"{target_url} --modules sqli,xss --verbose")
            scan_time = time.time() - start_time
            
            print(f"  ✓ Scan completed in {scan_time:.2f}s")
            
            # Analyze results
            total_vulns = len(scan_cmd.results.get('vulnerabilities', []))
            print(f"  📊 Found {total_vulns} vulnerabilities")
            
            if total_vulns == 0:
                print("  ⚠️  No vulnerabilities found - consider:")
                print("      • Disabling AI filtering")
                print("      • Using 'advanced' payload level")
                print("      • Increasing timeout values")
                print("      • Testing against a known vulnerable target")
            
            return {
                'success': True,
                'scan_time': scan_time,
                'vulnerabilities_found': total_vulns
            }
            
        except Exception as e:
            scan_time = time.time() - start_time
            print(f"  ✗ Scan failed after {scan_time:.2f}s: {str(e)}")
            return {
                'success': False,
                'scan_time': scan_time,
                'error': str(e)
            }
    
    def generate_optimized_config(self, recommended_timeout=None):
        """Generate an optimized configuration for better performance."""
        print("\n📝 Generating optimized configuration...")
        
        if not recommended_timeout:
            recommended_timeout = 25
        
        optimized_config = f"""
# Optimized ReconScan Configuration for Better Vulnerability Detection
# Generated by ReconScan Performance Optimizer

defaults:
  network:
    timeout: {recommended_timeout}                    # Optimized based on network testing
    retry_attempts: 2                  # Reduced for faster scanning
    connection_pool_size: 100          # Improved connection handling
  
  scanning:
    threads: 3                         # Reduced to prevent rate limiting
    delay: 1.0                         # Increased for server politeness
    deep_scan: true                    # Enabled for better coverage
    scan_timeout: 600                  # 10 minutes for thorough scans
    max_urls: 2000                     # Increased URL discovery
    max_crawl_urls: 50                 # More comprehensive crawling
    max_discovered_urls: 100           # Better parameter discovery
    max_urls_for_testing: 100          # More thorough testing

payload_defaults:
  sql_injection:
    default_level: "advanced"          # Maximum payload coverage
    time_based_delay: 3                # Faster time-based detection
    false_positive_filtering: false    # Disabled for thorough detection
    max_payloads_per_param: 100        # Comprehensive payload testing
  
  xss:
    default_encoding: "all"            # All encoding types
    false_positive_filtering: false    # Disabled for thorough detection
    max_payloads_per_param: 75         # Comprehensive XSS testing
  
  command_injection:
    default_os: "both"                 # Test both Linux and Windows
    time_based_delay: 2                # Faster detection
    max_payloads_per_param: 50
  
  lfi:
    max_payloads_per_param: 60         # Comprehensive LFI testing
"""
        
        print("Optimized configuration:")
        print(optimized_config)
        
        # Save to file
        config_file = os.path.join(project_root, "config", "optimized_config.yaml")
        try:
            with open(config_file, 'w') as f:
                f.write(optimized_config.strip())
            print(f"\n💾 Optimized configuration saved to: {config_file}")
            print("   To use this configuration, replace your config/config.yaml with this file")
        except Exception as e:
            print(f"\n❌ Failed to save configuration: {str(e)}")

def main():
    """Main optimization routine."""
    print("🔧 ReconScan Performance Optimizer")
    print("=" * 50)
    
    optimizer = ScanOptimizer()
    
    # Test network performance
    recommended_timeout = optimizer.test_network_performance()
    
    # Analyze current configuration
    optimizer.analyze_current_config()
    
    # Ask for target URL for performance testing
    target_url = input("\n🎯 Enter target URL for performance testing (or press Enter to skip): ").strip()
    
    if target_url:
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Test scan performance
        performance_result = optimizer.test_scan_performance(target_url)
        
        if not performance_result['success']:
            print("\n⚠️  Scan failed - this indicates configuration issues that need addressing")
    
    # Generate optimized config
    optimizer.generate_optimized_config(recommended_timeout)
    
    print(f"\n✅ Optimization complete!")
    print(f"   Key recommendations:")
    print(f"   • Use timeout of {recommended_timeout}s or higher")
    print(f"   • Disable AI filtering for thorough detection")
    print(f"   • Use 'advanced' payload levels")
    print(f"   • Reduce thread count to 2-3 for stability")

if __name__ == "__main__":
    main() 