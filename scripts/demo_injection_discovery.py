#!/usr/bin/env python3
"""
ReconScan Injection Point Discovery Demonstration

This script demonstrates the capabilities of the professional injection point
discovery module, showing how it can identify and analyze potential SQL injection
attack surfaces across different types of web application inputs.
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scanner.commands.scanning.injection_discovery import (
    InjectionPointDiscovery,
    InjectionPointType,
    ParameterType
)

async def demonstrate_url_analysis():
    """Demonstrate URL parameter analysis capabilities."""
    print("=" * 60)
    print("🔍 URL PARAMETER ANALYSIS")
    print("=" * 60)
    
    discovery = InjectionPointDiscovery()
    
    # Test URLs with different parameter types
    test_urls = [
        "https://shop.example.com/products?id=123&category=electronics&sort=price",
        "https://blog.example.com/posts?author_id=42&published=true&search=sql%20injection",
        "https://api.example.com/users?email=admin@example.com&active=1&role=admin",
        "https://cms.example.com/admin?page=dashboard&user_id=100&debug=false"
    ]
    
    for url in test_urls:
        print(f"\n📋 Analyzing: {url}")
        points = discovery._analyze_url_parameters(url)
        
        if not points:
            print("   No parameters found")
            continue
        
        # Sort by priority (highest first)
        points.sort(key=lambda x: x.test_priority, reverse=True)
        
        print(f"   Found {len(points)} injection points:")
        for point in points:
            priority_indicator = "🔴" if point.test_priority >= 8 else "🟡" if point.test_priority >= 6 else "🟢"
            type_icon = "🔢" if point.parameter_type == ParameterType.NUMERIC else "📧" if point.parameter_type == ParameterType.EMAIL else "📝"
            
            print(f"   {priority_indicator} {type_icon} {point.name}: '{point.value}' [{point.parameter_type.value}] (Priority: {point.test_priority})")
            
            if point.notes:
                for note in point.notes:
                    print(f"      💡 {note}")

async def demonstrate_form_analysis():
    """Demonstrate form data analysis capabilities."""
    print("\n" + "=" * 60)
    print("📝 FORM DATA ANALYSIS")
    print("=" * 60)
    
    discovery = InjectionPointDiscovery()
    
    # Test different types of form data
    test_forms = [
        {
            "name": "User Login Form",
            "data": {
                "username": "admin",
                "password": "secret123",
                "user_id": "42",
                "remember_me": "true",
                "csrf_token": "abc123def456"
            }
        },
        {
            "name": "Product Search Form",
            "data": {
                "search_query": "laptop computer",
                "category_id": "15",
                "min_price": "100.00",
                "max_price": "2000.00",
                "in_stock": "1"
            }
        },
        {
            "name": "User Registration Form", 
            "data": {
                "email": "newuser@example.com",
                "age": "25",
                "country": "US",
                "preferences": ["newsletter", "promotions"],
                "profile_data": '{"theme": "dark", "language": "en"}'
            }
        }
    ]
    
    for form in test_forms:
        print(f"\n📋 Analyzing: {form['name']}")
        points = discovery._analyze_form_data("https://example.com/form", form['data'])
        
        # Sort by priority
        points.sort(key=lambda x: x.test_priority, reverse=True)
        
        print(f"   Found {len(points)} injection points:")
        for point in points:
            priority_indicator = "🔴" if point.test_priority >= 8 else "🟡" if point.test_priority >= 6 else "🟢"
            required_indicator = "⚠️" if point.is_required else "  "
            filtered_indicator = "🛡️" if point.appears_filtered else "  "
            
            print(f"   {priority_indicator} {required_indicator} {filtered_indicator} {point.name}: '{point.value}' [{point.parameter_type.value}] (Priority: {point.test_priority})")

async def demonstrate_json_analysis():
    """Demonstrate JSON data analysis capabilities."""
    print("\n" + "=" * 60)
    print("🌐 JSON DATA ANALYSIS")
    print("=" * 60)
    
    discovery = InjectionPointDiscovery()
    
    # Test complex nested JSON structures
    test_json_data = [
        {
            "name": "User API Request",
            "data": {
                "user": {
                    "id": 123,
                    "username": "admin",
                    "email": "admin@example.com",
                    "profile": {
                        "age": 30,
                        "country": "US",
                        "preferences": {
                            "theme": "dark",
                            "notifications": True
                        }
                    }
                },
                "action": "update_profile",
                "timestamp": "2023-12-01T10:30:00Z",
                "metadata": {
                    "client_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (compatible)"
                }
            }
        },
        {
            "name": "E-commerce Order",
            "data": {
                "order_id": 98765,
                "customer_id": 12345,
                "items": [
                    {"product_id": 101, "quantity": 2, "price": 29.99},
                    {"product_id": 205, "quantity": 1, "price": 15.50}
                ],
                "shipping": {
                    "method": "express",
                    "cost": 9.99,
                    "tracking_number": "TRK123456789"
                },
                "payment": {
                    "method": "credit_card",
                    "last_four": "1234",
                    "authorized": True
                }
            }
        }
    ]
    
    for json_test in test_json_data:
        print(f"\n📋 Analyzing: {json_test['name']}")
        points = discovery._analyze_json_data("https://example.com/api", json_test['data'])
        
        # Sort by priority and group by parent structure
        points.sort(key=lambda x: (x.nested_path.count('.'), x.test_priority), reverse=True)
        
        print(f"   Found {len(points)} injection points:")
        
        current_parent = None
        for point in points:
            parent_path = '.'.join(point.nested_path.split('.')[:-1]) if '.' in point.nested_path else "root"
            
            if parent_path != current_parent:
                print(f"   📁 {parent_path}:")
                current_parent = parent_path
            
            priority_indicator = "🔴" if point.test_priority >= 8 else "🟡" if point.test_priority >= 6 else "🟢"
            type_icon = "🔢" if point.parameter_type == ParameterType.NUMERIC else "📧" if point.parameter_type == ParameterType.EMAIL else "📝"
            
            print(f"      {priority_indicator} {type_icon} {point.name}: '{point.value}' [{point.parameter_type.value}]")

async def demonstrate_comprehensive_discovery():
    """Demonstrate comprehensive injection point discovery."""
    print("\n" + "=" * 60)
    print("🎯 COMPREHENSIVE DISCOVERY SIMULATION")
    print("=" * 60)
    
    # Create a mock session for demonstration
    class MockSession:
        async def get(self, url, timeout=None):
            return self
        
        async def __aenter__(self):
            return self
        
        async def __aexit__(self, *args):
            pass
        
        @property
        def status(self):
            return 200
        
        async def text(self):
            # Simulate a typical web application response
            return '''
            <!DOCTYPE html>
            <html>
            <head><title>Example App</title></head>
            <body>
                <h1>User Management</h1>
                <form method="post" action="/users/update">
                    <input type="hidden" name="csrf_token" value="abc123def456">
                    <label>User ID: <input type="number" name="user_id" value="123" required></label>
                    <label>Username: <input type="text" name="username" value="admin" required></label>
                    <label>Email: <input type="email" name="email" value="admin@example.com"></label>
                    <label>Role: 
                        <select name="role">
                            <option value="user">User</option>
                            <option value="admin" selected>Administrator</option>
                        </select>
                    </label>
                    <label>Bio: <textarea name="bio">System administrator</textarea></label>
                    <label>Active: <input type="checkbox" name="active" value="1" checked></label>
                    <button type="submit">Update User</button>
                </form>
                
                <form method="get" action="/users/search">
                    <input type="search" name="q" placeholder="Search users...">
                    <input type="number" name="limit" value="10" min="1" max="100">
                    <select name="sort">
                        <option value="name">Name</option>
                        <option value="created">Created Date</option>
                    </select>
                    <button type="submit">Search</button>
                </form>
            </body>
            </html>
            '''
        
        @property
        def cookies(self):
            class MockCookie:
                def __init__(self, key, value):
                    self.key = key
                    self.value = value
            
            return [
                MockCookie("sessionid", "sess_abc123def456ghi789"),
                MockCookie("user_preferences", "theme=dark&lang=en"),
                MockCookie("csrf_token", "token_xyz789abc123")
            ]
    
    # Initialize discovery with mock session
    mock_session = MockSession()
    discovery = InjectionPointDiscovery(session=mock_session)
    
    # Simulate comprehensive discovery
    target_url = "https://example.com/admin/users?page=1&filter=active&sort=name"
    additional_data = {
        "action": "bulk_update",
        "user_ids": [123, 456, 789],
        "changes": {
            "role": "user",
            "department": "IT"
        }
    }
    
    print(f"🎯 Target: {target_url}")
    print(f"📤 Additional Data: {json.dumps(additional_data, indent=2)}")
    
    try:
        result = await discovery.discover_injection_points(
            target_url,
            additional_data=additional_data,
            include_forms=True,
            include_headers=True,
            include_cookies=True
        )
        
        print(f"\n📊 DISCOVERY RESULTS")
        print(f"   ⏱️  Discovery time: {result.discovery_time:.3f} seconds")
        print(f"   📋 Total parameters: {result.total_parameters}")
        print(f"   🔴 High priority points: {result.high_priority_points}")
        print(f"   📝 Forms discovered: {result.forms_discovered}")
        print(f"   🍪 Cookies analyzed: {result.cookies_analyzed}")
        print(f"   🌐 Headers analyzed: {result.headers_analyzed}")
        
        if result.errors_encountered:
            print(f"   ⚠️  Errors encountered: {len(result.errors_encountered)}")
            for error in result.errors_encountered:
                print(f"      - {error}")
        
        # Show top priority injection points
        print(f"\n🎯 TOP PRIORITY INJECTION POINTS:")
        high_priority_points = result.get_priority_points(min_priority=7)
        
        if not high_priority_points:
            print("   No high-priority points found")
        else:
            for i, point in enumerate(high_priority_points[:10]):  # Show top 10
                location_icon = {"query_string": "🔗", "form_data": "📝", "json_body": "🌐", "http_headers": "📡", "cookies": "🍪"}.get(point.location, "📄")
                
                print(f"   {i+1:2d}. {location_icon} {point.name} ({point.injection_type.value})")
                print(f"       Value: '{point.value}' [{point.parameter_type.value}]")
                print(f"       Priority: {point.test_priority}/10, Location: {point.location}")
                
                if point.notes:
                    print(f"       Notes: {', '.join(point.notes)}")
                print()
        
        # Show breakdown by injection point type
        print(f"📈 BREAKDOWN BY TYPE:")
        type_counts = {}
        for point in result.injection_points:
            point_type = point.injection_type.value
            type_counts[point_type] = type_counts.get(point_type, 0) + 1
        
        for point_type, count in sorted(type_counts.items()):
            type_icon = {"query_param": "🔗", "form_field": "📝", "json_field": "🌐", "header": "📡", "cookie": "🍪", "post_param": "📤"}.get(point_type, "📄")
            print(f"   {type_icon} {point_type.replace('_', ' ').title()}: {count} points")
        
    except Exception as e:
        print(f"❌ Error during discovery: {str(e)}")

async def main():
    """Main demonstration function."""
    print("🔍 RECONSCAN INJECTION POINT DISCOVERY DEMONSTRATION")
    print("=" * 60)
    print("This demonstration shows the capabilities of the professional")
    print("injection point discovery module for SQL injection testing.")
    print()
    
    try:
        # Run all demonstrations
        await demonstrate_url_analysis()
        await demonstrate_form_analysis()
        await demonstrate_json_analysis()
        await demonstrate_comprehensive_discovery()
        
        print("\n" + "=" * 60)
        print("✅ DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("The injection point discovery module has successfully identified")
        print("and analyzed potential SQL injection attack surfaces across:")
        print("• URL query parameters with intelligent type detection")
        print("• Form data with priority scoring and requirement analysis")
        print("• JSON structures with nested path tracking")
        print("• HTTP headers and cookies")
        print("• Complex data structures with filtering detection")
        print()
        print("Next steps: Integrate with payload generation and testing engines")
        print("for complete SQL injection vulnerability assessment.")
        
    except Exception as e:
        print(f"\n❌ Demonstration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    # Run the demonstration
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 