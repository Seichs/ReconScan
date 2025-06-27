#!/usr/bin/env python3
"""
ReconScan SQL Injection Payload Crafting Engine - Demonstration Script

This script demonstrates the comprehensive capabilities of our professional
payload crafting engine, showcasing features that rival industry-leading
tools like sqlmap.

Features demonstrated:
- Dynamic template-based payload generation
- Context-aware payload adaptation
- Database-specific payload optimization
- Advanced WAF evasion techniques
- Intelligent payload scoring and ranking
- Integration with injection discovery

Usage:
    python scripts/demo_payload_crafting.py

Author: ReconScan Security Framework
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
import json
from datetime import datetime

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import our modules
from scanner.commands.scanning.vulnerability_scanners.sql_injection import (
    PayloadCraftingEngine,
    PayloadTemplate,
    PayloadCraftingContext,
    DatabaseType,
    InjectionTechnique,
    EncodingType
)
from scanner.commands.scanning.shared.injection_discovery import (
    InjectionPoint,
    InjectionPointType,
    ParameterType
)

class PayloadCraftingDemo:
    """Professional demonstration of payload crafting capabilities."""
    
    def __init__(self):
        """Initialize the demonstration with crafting engine."""
        print("🛠️  ReconScan SQL Injection Payload Crafting Engine Demo")
        print("=" * 65)
        print()
        
        # Initialize the payload crafting engine
        print("Initializing payload crafting engine...")
        self.engine = PayloadCraftingEngine()
        print(f"✅ Engine initialized with {self._count_templates()} payload templates")
        print()
        
        # Create realistic test scenarios
        self._create_test_scenarios()
        
    def _count_templates(self) -> int:
        """Count total number of payload templates loaded."""
        total = 0
        for technique_templates in self.engine.templates.values():
            for db_templates in technique_templates.values():
                total += len(db_templates)
        return total
        
    def _create_test_scenarios(self):
        """Create realistic injection point scenarios for testing."""
        
        # E-commerce product ID (high-priority numeric)
        self.ecommerce_id = InjectionPoint(
            name="product_id",
            value="1337",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="https://shop.example.com/products?product_id=1337",
            location="GET /products?product_id=1337"
        )
        
        # Login form username (authentication bypass target)
        self.login_username = InjectionPoint(
            name="username",
            value="admin",
            injection_type=InjectionPointType.POST_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="https://example.com/admin/login",
            method="POST",
            location="POST /admin/login"
        )
        
        # Search functionality (wide attack surface)
        self.search_query = InjectionPoint(
            name="q",
            value="laptop computers",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="https://example.com/search?q=laptop+computers",
            location="GET /search?q=laptop+computers"
        )
        
        # JSON API user object (modern application)
        self.api_user_id = InjectionPoint(
            name="user.profile.id",
            value="42",
            injection_type=InjectionPointType.JSON_FIELD,
            parameter_type=ParameterType.NUMERIC,
            url="https://example.com/api/v1/users/profile",
            method="POST",
            location="POST /api/v1/users/profile"
        )
        
        # Cookie session ID (session hijacking potential)
        self.session_cookie = InjectionPoint(
            name="PHPSESSID",
            value="abc123def456",
            injection_type=InjectionPointType.COOKIE,
            parameter_type=ParameterType.STRING,
            url="https://example.com/app",
            location="Cookie: PHPSESSID=abc123def456"
        )
        
        # XML API data (enterprise application)
        self.xml_user_id = InjectionPoint(
            name="user_id",
            value="999",
            injection_type=InjectionPointType.XML_ATTRIBUTE,
            parameter_type=ParameterType.NUMERIC,
            url="https://example.com/soap/userservice",
            method="POST",
            location="POST /soap/userservice"
        )
    
    def run_complete_demo(self):
        """Run the complete payload crafting demonstration."""
        print("🎯 Starting Comprehensive Payload Crafting Demonstration")
        print()
        
        # 1. Template system overview
        self.demo_template_system()
        
        # 2. Basic payload generation
        self.demo_basic_payload_generation()
        
        # 3. Context-aware adaptation
        self.demo_context_aware_adaptation()
        
        # 4. Database-specific targeting
        self.demo_database_specific_targeting()
        
        # 5. Injection technique comparison
        self.demo_injection_technique_comparison()
        
        # 6. WAF evasion capabilities
        self.demo_waf_evasion()
        
        # 7. Advanced encoding methods
        self.demo_encoding_methods()
        
        # 8. Real-world scenario testing
        self.demo_real_world_scenarios()
        
        # 9. Performance and analytics
        self.demo_performance_analytics()
        
        print("🎉 Payload Crafting Engine Demonstration Complete!")
        print()
        print("The ReconScan payload crafting engine demonstrates professional-grade")
        print("capabilities rivaling industry-leading SQL injection tools.")
    
    def demo_template_system(self):
        """Demonstrate the template system architecture."""
        print("📋 Template System Architecture")
        print("-" * 40)
        
        # Show template organization
        print("Template Organization:")
        for technique, db_templates in self.engine.templates.items():
            technique_name = technique.value.title().replace('_', ' ')
            print(f"  • {technique_name}:")
            
            for db_type, templates in db_templates.items():
                db_name = db_type.value.title()
                template_count = len(templates)
                print(f"    - {db_name}: {template_count} templates")
        
        print()
        
        # Show a sample template
        mysql_boolean_templates = self.engine.templates[InjectionTechnique.BOOLEAN_BASED][DatabaseType.MYSQL]
        if mysql_boolean_templates:
            sample_template = mysql_boolean_templates[0]
            print("Sample Template Structure:")
            print(f"  ID: {sample_template.id}")
            print(f"  Name: {sample_template.name}")
            print(f"  Technique: {sample_template.technique.value}")
            print(f"  Database: {sample_template.database.value}")
            print(f"  Template: {sample_template.template}")
            print(f"  Risk Level: {sample_template.risk_level}/5")
            print(f"  Description: {sample_template.description}")
        
        print()
    
    def demo_basic_payload_generation(self):
        """Demonstrate basic payload generation capabilities."""
        print("⚡ Basic Payload Generation")
        print("-" * 40)
        
        # Generate payloads for the e-commerce product ID
        print(f"Target: {self.ecommerce_id.location}")
        print(f"Parameter: {self.ecommerce_id.name} = {self.ecommerce_id.value}")
        print(f"Type: {self.ecommerce_id.parameter_type.value}")
        print(f"Priority: {self.ecommerce_id.test_priority}/10")
        print()
        
        # Generate basic payloads
        payloads = self.engine.craft_payloads(
            injection_point=self.ecommerce_id,
            max_payloads=8
        )
        
        print("Generated Payloads:")
        for i, (payload, template) in enumerate(payloads, 1):
            technique_name = template.technique.value.replace('_', '-')
            db_name = template.database.value
            print(f"  {i:2d}. [{technique_name:12}] [{db_name:8}] {payload}")
        
        print()
    
    def demo_context_aware_adaptation(self):
        """Demonstrate context-aware payload adaptation."""
        print("🎯 Context-Aware Payload Adaptation")
        print("-" * 40)
        
        # Compare payloads for different parameter types
        test_points = [
            ("Numeric ID", self.ecommerce_id),
            ("String Search", self.search_query),
            ("JSON Field", self.api_user_id)
        ]
        
        for name, injection_point in test_points:
            print(f"{name} ({injection_point.parameter_type.value}):")
            
            # Generate context-aware payloads
            payloads = self.engine.craft_payloads(
                injection_point=injection_point,
                techniques=[InjectionTechnique.BOOLEAN_BASED],
                max_payloads=3
            )
            
            for payload, template in payloads:
                print(f"  → {payload}")
            print()
    
    def demo_database_specific_targeting(self):
        """Demonstrate database-specific payload targeting."""
        print("🗄️  Database-Specific Targeting")
        print("-" * 40)
        
        # Show payloads for different database types
        databases = [DatabaseType.MYSQL, DatabaseType.POSTGRESQL, DatabaseType.MSSQL]
        
        for db_type in databases:
            print(f"{db_type.value.upper()} Optimized Payloads:")
            
            payloads = self.engine.craft_payloads(
                injection_point=self.login_username,
                database_types=[db_type],
                techniques=[InjectionTechnique.ERROR_BASED],
                max_payloads=3
            )
            
            for payload, template in payloads:
                print(f"  → {payload}")
            print()
    
    def demo_injection_technique_comparison(self):
        """Demonstrate different SQL injection techniques."""
        print("⚔️  Injection Technique Comparison")
        print("-" * 40)
        
        techniques = [
            InjectionTechnique.BOOLEAN_BASED,
            InjectionTechnique.ERROR_BASED,
            InjectionTechnique.TIME_BASED,
            InjectionTechnique.UNION_BASED
        ]
        
        for technique in techniques:
            info = self.engine.get_technique_info(technique)
            print(f"{info['name']}:")
            print(f"  Description: {info['description']}")
            print(f"  Speed: {info['speed']} | Stealth: {info['stealth']} | Reliability: {info['reliability']}")
            
            # Show sample payload
            payloads = self.engine.craft_payloads(
                injection_point=self.search_query,
                techniques=[technique],
                max_payloads=1
            )
            
            if payloads:
                payload, template = payloads[0]
                print(f"  Sample: {payload}")
            print()
    
    def demo_waf_evasion(self):
        """Demonstrate WAF evasion capabilities."""
        print("🛡️  WAF Evasion Techniques")
        print("-" * 40)
        
        # Create context with detected WAF
        waf_context = PayloadCraftingContext(
            injection_point=self.search_query,
            detected_waf='cloudflare'
        )
        
        # Generate normal payloads
        normal_payloads = self.engine.craft_payloads(
            injection_point=self.search_query,
            max_payloads=2
        )
        
        print("Normal Payloads:")
        for payload, template in normal_payloads:
            print(f"  → {payload}")
        
        # Apply WAF evasion
        evasive_payloads = self.engine._apply_waf_evasion(normal_payloads, waf_context)
        
        print("\nCloudflare Evasive Payloads:")
        for payload, template in evasive_payloads[:4]:  # Show first 4
            print(f"  → {payload}")
        
        # Show available evasion patterns
        cf_patterns = self.engine.waf_evasion_patterns['cloudflare']
        print(f"\nAvailable Evasion Methods:")
        print(f"  • Space Replacements: {len(cf_patterns['space_replacements'])} variants")
        print(f"  • Keyword Obfuscation: {len(cf_patterns['keyword_obfuscation'])} keywords")
        print(f"  • Comment Variations: {len(cf_patterns['comment_variations'])} types")
        print()
    
    def demo_encoding_methods(self):
        """Demonstrate advanced encoding methods."""
        print("🔐 Advanced Encoding Methods")
        print("-" * 40)
        
        test_payload = "SELECT user FROM accounts"
        
        encoding_methods = [
            (EncodingType.URL_ENCODE, "URL Encoding"),
            (EncodingType.HEX_ENCODE, "Hexadecimal"),
            (EncodingType.BASE64_ENCODE, "Base64"),
            (EncodingType.UNICODE_ENCODE, "Unicode"),
            (EncodingType.CHAR_FUNCTION, "CHAR Function"),
            (EncodingType.HTML_ENTITY, "HTML Entities")
        ]
        
        print(f"Original: {test_payload}")
        print()
        
        for encoding_type, description in encoding_methods:
            if encoding_type in self.engine.encoders:
                encoder = self.engine.encoders[encoding_type]
                try:
                    encoded = encoder(test_payload)
                    # Truncate long encodings for display
                    if len(encoded) > 80:
                        encoded = encoded[:77] + "..."
                    print(f"{description:15}: {encoded}")
                except Exception as e:
                    print(f"{description:15}: Error - {str(e)}")
        
        print()
    
    def demo_real_world_scenarios(self):
        """Demonstrate real-world attack scenarios."""
        print("🌍 Real-World Attack Scenarios")
        print("-" * 40)
        
        scenarios = [
            {
                'name': 'E-commerce Authentication Bypass',
                'injection_point': self.login_username,
                'techniques': [InjectionTechnique.BOOLEAN_BASED, InjectionTechnique.ERROR_BASED],
                'description': 'Admin login bypass attempt'
            },
            {
                'name': 'API Data Extraction',
                'injection_point': self.api_user_id,
                'techniques': [InjectionTechnique.UNION_BASED, InjectionTechnique.ERROR_BASED],
                'description': 'User data extraction via API'
            },
            {
                'name': 'Session Hijacking',
                'injection_point': self.session_cookie,
                'techniques': [InjectionTechnique.BOOLEAN_BASED, InjectionTechnique.TIME_BASED],
                'description': 'Session manipulation attack'
            }
        ]
        
        for scenario in scenarios:
            print(f"Scenario: {scenario['name']}")
            print(f"Description: {scenario['description']}")
            print(f"Target: {scenario['injection_point'].location}")
            
            payloads = self.engine.craft_payloads(
                injection_point=scenario['injection_point'],
                techniques=scenario['techniques'],
                max_payloads=3
            )
            
            print("Attack Payloads:")
            for i, (payload, template) in enumerate(payloads, 1):
                technique_name = template.technique.value.replace('_', '-')
                print(f"  {i}. [{technique_name}] {payload}")
            print()
    
    def demo_performance_analytics(self):
        """Demonstrate performance and analytics features."""
        print("📊 Performance & Analytics")
        print("-" * 40)
        
        # Generate comprehensive payload set
        print("Generating comprehensive payload set...")
        start_time = datetime.now()
        
        all_payloads = self.engine.craft_payloads(
            injection_point=self.ecommerce_id,
            max_payloads=50
        )
        
        end_time = datetime.now()
        generation_time = (end_time - start_time).total_seconds()
        
        # Analyze payload distribution
        technique_counts = {}
        database_counts = {}
        
        for payload, template in all_payloads:
            technique = template.technique
            database = template.database
            
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
            database_counts[database] = database_counts.get(database, 0) + 1
        
        print(f"✅ Generated {len(all_payloads)} payloads in {generation_time:.3f} seconds")
        print(f"   Rate: {len(all_payloads)/generation_time:.1f} payloads/second")
        print()
        
        print("Technique Distribution:")
        for technique, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True):
            technique_name = technique.value.replace('_', ' ').title()
            percentage = (count / len(all_payloads)) * 100
            print(f"  • {technique_name}: {count} payloads ({percentage:.1f}%)")
        print()
        
        print("Database Target Distribution:")
        for database, count in sorted(database_counts.items(), key=lambda x: x[1], reverse=True):
            database_name = database.value.title()
            percentage = (count / len(all_payloads)) * 100
            print(f"  • {database_name}: {count} payloads ({percentage:.1f}%)")
        print()
        
        # Simulate payload success tracking
        print("Payload Success Rate Simulation:")
        test_payloads = [payload for payload, template in all_payloads[:5]]
        
        for payload in test_payloads:
            # Simulate some successful and failed attempts
            self.engine.update_payload_success(payload, True)
            self.engine.update_payload_success(payload, True)
            self.engine.update_payload_success(payload, False)
        
        print(f"✅ Tracked success rates for {len(test_payloads)} payloads")
        print(f"   Learning algorithm adapts payload selection based on historical success")
        print()

def main():
    """Run the payload crafting demonstration."""
    try:
        demo = PayloadCraftingDemo()
        demo.run_complete_demo()
        
        print("💡 Key Capabilities Demonstrated:")
        print("   • Dynamic template-based payload generation")
        print("   • Context-aware parameter type adaptation")
        print("   • Database-specific payload optimization")
        print("   • Multiple injection technique support")
        print("   • Advanced WAF evasion methods")
        print("   • Professional encoding capabilities")
        print("   • Real-world attack scenario modeling")
        print("   • Performance optimization and analytics")
        print()
        print("🚀 Ready for integration with detection and exploitation modules!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 