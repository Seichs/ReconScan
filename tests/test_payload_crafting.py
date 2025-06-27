"""
Test Suite for SQL Injection Payload Crafting Engine

Comprehensive tests for the payload crafting engine including:
- Template rendering and validation
- Context-aware payload generation
- Database-specific payload crafting
- WAF evasion technique testing
- Encoding function validation
- Payload scoring and ranking
- Integration with injection discovery

Author: ReconScan Security Framework
"""

import pytest
import unittest
import hashlib
from unittest.mock import Mock, patch
from dataclasses import dataclass
from typing import List, Dict, Any

# Import the modules we're testing
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

class TestPayloadTemplate(unittest.TestCase):
    """Test cases for payload template functionality."""
    
    def setUp(self):
        """Set up test fixtures for each test."""
        self.template = PayloadTemplate(
            id="test_template",
            name="Test Template",
            technique=InjectionTechnique.BOOLEAN_BASED,
            database=DatabaseType.MYSQL,
            template="SELECT * FROM users WHERE id = {PREFIX}1 AND {CONDITION}{SUFFIX}",
            description="Test template for unit testing",
            risk_level=3,
            success_indicators=["different response", "data returned"]
        )
    
    def test_template_initialization(self):
        """Test that templates initialize correctly."""
        self.assertEqual(self.template.id, "test_template")
        self.assertEqual(self.template.technique, InjectionTechnique.BOOLEAN_BASED)
        self.assertEqual(self.template.database, DatabaseType.MYSQL)
        self.assertEqual(self.template.risk_level, 3)
        self.assertIn("different response", self.template.success_indicators)
    
    def test_template_rendering_basic(self):
        """Test basic template rendering with context."""
        context = {
            "prefix": "'",
            "condition": "1=1",
            "suffix": "--"
        }
        
        rendered = self.template.render(context)
        expected = "SELECT * FROM users WHERE id = '1 AND 1=1--"
        self.assertEqual(rendered, expected)
    
    def test_template_rendering_missing_variables(self):
        """Test template rendering with missing context variables."""
        context = {
            "prefix": "'",
            "condition": "1=1"
            # Missing suffix
        }
        
        rendered = self.template.render(context)
        # Should leave unmatched placeholder
        self.assertIn("{SUFFIX}", rendered)
    
    def test_template_rendering_empty_context(self):
        """Test template rendering with empty context."""
        context = {}
        
        rendered = self.template.render(context)
        # Should contain original placeholders
        self.assertIn("{PREFIX}", rendered)
        self.assertIn("{CONDITION}", rendered)
        self.assertIn("{SUFFIX}", rendered)

class TestPayloadCraftingContext(unittest.TestCase):
    """Test cases for payload crafting context."""
    
    def setUp(self):
        """Set up test injection points for context testing."""
        self.numeric_injection_point = InjectionPoint(
            name="id",
            value="123",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="http://example.com/test?id=123",
            location="GET parameter"
        )
        
        self.string_injection_point = InjectionPoint(
            name="username",
            value="admin",
            injection_type=InjectionPointType.POST_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/login",
            method="POST",
            location="POST parameter"
        )
        
        self.json_injection_point = InjectionPoint(
            name="user.id",
            value="42",
            injection_type=InjectionPointType.JSON_FIELD,
            parameter_type=ParameterType.JSON_OBJECT,
            url="http://example.com/api/user",
            method="POST",
            location="JSON field"
        )
    
    def test_context_initialization(self):
        """Test context initialization with injection point."""
        context = PayloadCraftingContext(injection_point=self.numeric_injection_point)
        
        self.assertEqual(context.injection_point, self.numeric_injection_point)
        self.assertEqual(context.database_type, DatabaseType.UNKNOWN)
        self.assertEqual(context.time_delay, 5.0)
        self.assertIsNone(context.detected_waf)
    
    def test_quote_char_numeric(self):
        """Test quote character selection for numeric parameters."""
        context = PayloadCraftingContext(injection_point=self.numeric_injection_point)
        self.assertEqual(context.get_quote_char(), "")
    
    def test_quote_char_string(self):
        """Test quote character selection for string parameters."""
        context = PayloadCraftingContext(injection_point=self.string_injection_point)
        self.assertEqual(context.get_quote_char(), "'")
    
    def test_quote_char_json(self):
        """Test quote character selection for JSON parameters."""
        context = PayloadCraftingContext(injection_point=self.json_injection_point)
        self.assertEqual(context.get_quote_char(), '"')
    
    def test_context_with_custom_variables(self):
        """Test context with custom variables."""
        custom_vars = {"custom_field": "test_value", "priority": 5}
        context = PayloadCraftingContext(
            injection_point=self.numeric_injection_point,
            custom_variables=custom_vars
        )
        
        self.assertEqual(context.custom_variables["custom_field"], "test_value")
        self.assertEqual(context.custom_variables["priority"], 5)

class TestPayloadCraftingEngine(unittest.TestCase):
    """Test cases for the main payload crafting engine."""
    
    def setUp(self):
        """Set up payload crafting engine for testing."""
        self.engine = PayloadCraftingEngine()
        
        # Test injection points
        self.numeric_injection_point = InjectionPoint(
            name="id",
            value="123",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="http://example.com/test?id=123",
            location="GET parameter"
        )
        
        self.string_injection_point = InjectionPoint(
            name="search",
            value="test",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/search?q=test",
            location="GET parameter"
        )
    
    def test_engine_initialization(self):
        """Test that the engine initializes correctly."""
        self.assertIsInstance(self.engine, PayloadCraftingEngine)
        self.assertIsInstance(self.engine.templates, dict)
        self.assertIsInstance(self.engine.encoders, dict)
        self.assertIsInstance(self.engine.waf_evasion_patterns, dict)
    
    def test_templates_loaded(self):
        """Test that templates are loaded for all techniques."""
        expected_techniques = [
            InjectionTechnique.BOOLEAN_BASED,
            InjectionTechnique.ERROR_BASED,
            InjectionTechnique.TIME_BASED,
            InjectionTechnique.UNION_BASED,
            InjectionTechnique.STACKED_QUERIES
        ]
        
        for technique in expected_techniques:
            self.assertIn(technique, self.engine.templates)
            self.assertIsInstance(self.engine.templates[technique], dict)
    
    def test_boolean_based_templates(self):
        """Test boolean-based template loading."""
        boolean_templates = self.engine.templates[InjectionTechnique.BOOLEAN_BASED]
        
        # Should have MySQL templates
        self.assertIn(DatabaseType.MYSQL, boolean_templates)
        mysql_templates = boolean_templates[DatabaseType.MYSQL]
        self.assertGreater(len(mysql_templates), 0)
        
        # Check template structure
        first_template = mysql_templates[0]
        self.assertIsInstance(first_template, PayloadTemplate)
        self.assertEqual(first_template.technique, InjectionTechnique.BOOLEAN_BASED)
        self.assertEqual(first_template.database, DatabaseType.MYSQL)
    
    def test_error_based_templates(self):
        """Test error-based template loading."""
        error_templates = self.engine.templates[InjectionTechnique.ERROR_BASED]
        
        # Should have templates for multiple databases
        self.assertIn(DatabaseType.MYSQL, error_templates)
        self.assertIn(DatabaseType.POSTGRESQL, error_templates)
        self.assertIn(DatabaseType.MSSQL, error_templates)
        
        # Check MySQL EXTRACTVALUE template
        mysql_templates = error_templates[DatabaseType.MYSQL]
        extractvalue_template = next(
            (t for t in mysql_templates if "extractvalue" in t.id.lower()), 
            None
        )
        self.assertIsNotNone(extractvalue_template)
        self.assertIn("EXTRACTVALUE", extractvalue_template.template)
    
    def test_time_based_templates(self):
        """Test time-based template loading."""
        time_templates = self.engine.templates[InjectionTechnique.TIME_BASED]
        
        # Check MySQL SLEEP template
        mysql_templates = time_templates[DatabaseType.MYSQL]
        sleep_template = next(
            (t for t in mysql_templates if "sleep" in t.id.lower()), 
            None
        )
        self.assertIsNotNone(sleep_template)
        self.assertIn("SLEEP", sleep_template.template)
        self.assertEqual(sleep_template.time_delay, 5.0)
    
    def test_union_based_templates(self):
        """Test UNION-based template loading."""
        union_templates = self.engine.templates[InjectionTechnique.UNION_BASED]
        
        # Should have universal templates
        self.assertIn(DatabaseType.UNKNOWN, union_templates)
        universal_templates = union_templates[DatabaseType.UNKNOWN]
        
        # Check for ORDER BY template
        order_by_template = next(
            (t for t in universal_templates if "order" in t.id.lower()), 
            None
        )
        self.assertIsNotNone(order_by_template)
        self.assertTrue(order_by_template.requires_columns)
    
    def test_craft_payloads_basic(self):
        """Test basic payload crafting functionality."""
        payloads = self.engine.craft_payloads(
            injection_point=self.numeric_injection_point,
            max_payloads=10
        )
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertLessEqual(len(payloads), 10)
        
        # Check payload structure
        payload, template = payloads[0]
        self.assertIsInstance(payload, str)
        self.assertIsInstance(template, PayloadTemplate)
    
    def test_craft_payloads_technique_filtering(self):
        """Test payload crafting with specific techniques."""
        payloads = self.engine.craft_payloads(
            injection_point=self.numeric_injection_point,
            techniques=[InjectionTechnique.BOOLEAN_BASED],
            max_payloads=5
        )
        
        self.assertGreater(len(payloads), 0)
        
        # All payloads should be boolean-based
        for payload, template in payloads:
            self.assertEqual(template.technique, InjectionTechnique.BOOLEAN_BASED)
    
    def test_craft_payloads_database_filtering(self):
        """Test payload crafting with specific database types."""
        payloads = self.engine.craft_payloads(
            injection_point=self.numeric_injection_point,
            database_types=[DatabaseType.MYSQL],
            max_payloads=5
        )
        
        self.assertGreater(len(payloads), 0)
        
        # All payloads should be MySQL-specific
        for payload, template in payloads:
            self.assertEqual(template.database, DatabaseType.MYSQL)
    
    def test_contextual_prefixes_numeric(self):
        """Test contextual prefix generation for numeric parameters."""
        context = PayloadCraftingContext(injection_point=self.numeric_injection_point)
        prefixes = self.engine._get_contextual_prefixes(context)
        
        self.assertIn("", prefixes)  # Empty prefix for numeric
        self.assertIn(" ", prefixes)  # Space prefix
    
    def test_contextual_prefixes_string(self):
        """Test contextual prefix generation for string parameters."""
        context = PayloadCraftingContext(injection_point=self.string_injection_point)
        prefixes = self.engine._get_contextual_prefixes(context)
        
        self.assertIn("'", prefixes)
        self.assertIn("\"", prefixes)
        self.assertIn("') ", prefixes)
    
    def test_contextual_suffixes(self):
        """Test contextual suffix generation."""
        context = PayloadCraftingContext(injection_point=self.numeric_injection_point)
        suffixes = self.engine._get_contextual_suffixes(context)
        
        self.assertIn("--", suffixes)
        self.assertIn("#", suffixes)
        self.assertIn("/**/", suffixes)
    
    def test_payload_scoring(self):
        """Test payload scoring functionality."""
        template = PayloadTemplate(
            id="test_template",
            name="Test",
            technique=InjectionTechnique.ERROR_BASED,
            database=DatabaseType.MYSQL,
            template="SELECT {QUERY}",
            description="Test template",
            risk_level=4
        )
        
        context = PayloadCraftingContext(injection_point=self.numeric_injection_point)
        payload = "SELECT database()"
        
        score = self.engine._calculate_payload_score(payload, template, context)
        
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
    
    def test_waf_evasion_patterns(self):
        """Test WAF evasion pattern initialization."""
        patterns = self.engine.waf_evasion_patterns
        
        # Should have patterns for common WAFs
        self.assertIn('cloudflare', patterns)
        self.assertIn('akamai', patterns)
        self.assertIn('generic', patterns)
        
        # Check Cloudflare patterns
        cf_patterns = patterns['cloudflare']
        self.assertIn('space_replacements', cf_patterns)
        self.assertIn('keyword_obfuscation', cf_patterns)
        
        # Check keyword obfuscation
        keyword_obf = cf_patterns['keyword_obfuscation']
        self.assertIn('SELECT', keyword_obf)
        self.assertIn('UNION', keyword_obf)
    
    def test_apply_waf_evasion(self):
        """Test WAF evasion application."""
        template = PayloadTemplate(
            id="test_template",
            name="Test",
            technique=InjectionTechnique.BOOLEAN_BASED,
            database=DatabaseType.MYSQL,
            template="SELECT * FROM users",
            description="Test template"
        )
        
        context = PayloadCraftingContext(
            injection_point=self.numeric_injection_point,
            detected_waf='cloudflare'
        )
        
        original_payloads = [("SELECT * FROM users WHERE id=1", template)]
        evasive_payloads = self.engine._apply_waf_evasion(original_payloads, context)
        
        self.assertIsInstance(evasive_payloads, list)
        # Should generate some evasive variants
        if len(evasive_payloads) > 0:
            evasive_payload, evasive_template = evasive_payloads[0]
            self.assertNotEqual(evasive_payload, "SELECT * FROM users WHERE id=1")
    
    def test_encoders_initialization(self):
        """Test that all encoders are properly initialized."""
        expected_encoders = [
            EncodingType.URL_ENCODE,
            EncodingType.DOUBLE_URL_ENCODE,
            EncodingType.UNICODE_ENCODE,
            EncodingType.HEX_ENCODE,
            EncodingType.BASE64_ENCODE,
            EncodingType.HTML_ENTITY,
            EncodingType.CHAR_FUNCTION,
            EncodingType.CONCAT_FUNCTION
        ]
        
        for encoder_type in expected_encoders:
            self.assertIn(encoder_type, self.engine.encoders)
            self.assertTrue(callable(self.engine.encoders[encoder_type]))
    
    def test_url_encoding(self):
        """Test URL encoding functionality."""
        test_payload = "SELECT * FROM users WHERE id='1'"
        encoded = self.engine._url_encode(test_payload)
        
        self.assertIn("%20", encoded)  # Space should be encoded
        self.assertIn("%3D", encoded)  # = should be encoded
        self.assertIn("%27", encoded)  # ' should be encoded
    
    def test_double_url_encoding(self):
        """Test double URL encoding functionality."""
        test_payload = "SELECT * FROM users"
        encoded = self.engine._double_url_encode(test_payload)
        
        # Should be double encoded
        self.assertIn("%2520", encoded)  # Double encoded space
    
    def test_unicode_encoding(self):
        """Test Unicode encoding functionality."""
        test_payload = "SELECT"
        encoded = self.engine._unicode_encode(test_payload)
        
        self.assertIn("\\u0053", encoded)  # S
        self.assertIn("\\u0045", encoded)  # E
    
    def test_hex_encoding(self):
        """Test hexadecimal encoding functionality."""
        test_payload = "SELECT"
        encoded = self.engine._hex_encode(test_payload)
        
        self.assertTrue(encoded.startswith("0x"))
        self.assertIn("53454c454354", encoded.lower())  # "SELECT" in hex
    
    def test_base64_encoding(self):
        """Test Base64 encoding functionality."""
        test_payload = "SELECT"
        encoded = self.engine._base64_encode(test_payload)
        
        # "SELECT" in base64 is "U0VMRUNU"
        self.assertEqual(encoded, "U0VMRUNU")
    
    def test_html_entity_encoding(self):
        """Test HTML entity encoding functionality."""
        test_payload = "SELECT"
        encoded = self.engine._html_entity_encode(test_payload)
        
        self.assertIn("&#83;", encoded)  # S
        self.assertIn("&#69;", encoded)  # E
    
    def test_char_function_encoding(self):
        """Test CHAR function encoding functionality."""
        test_payload = "AB"
        encoded = self.engine._char_function_encode(test_payload)
        
        self.assertTrue(encoded.startswith("CHAR("))
        self.assertIn("65,66", encoded)  # ASCII codes for A,B
    
    def test_concat_function_encoding(self):
        """Test CONCAT function encoding functionality."""
        test_payload = "AB"
        encoded = self.engine._concat_function_encode(test_payload)
        
        self.assertTrue(encoded.startswith("CONCAT("))
        self.assertIn("CHAR(65)", encoded)  # A
        self.assertIn("CHAR(66)", encoded)  # B
    
    def test_payload_success_tracking(self):
        """Test payload success rate tracking."""
        test_payload = "SELECT * FROM users WHERE id=1"
        
        # Initial update
        self.engine.update_payload_success(test_payload, True)
        
        # Should have a success rate entry
        payload_hash = hashlib.md5(test_payload.encode()).hexdigest()[:8]
        self.assertIn(payload_hash, self.engine.payload_success_rates)
        
        # Success should increase rate
        initial_rate = self.engine.payload_success_rates[payload_hash]
        self.engine.update_payload_success(test_payload, True)
        updated_rate = self.engine.payload_success_rates[payload_hash]
        self.assertGreater(updated_rate, initial_rate)
        
        # Failure should decrease rate
        self.engine.update_payload_success(test_payload, False)
        final_rate = self.engine.payload_success_rates[payload_hash]
        self.assertLess(final_rate, updated_rate)
    
    def test_technique_info(self):
        """Test technique information retrieval."""
        info = self.engine.get_technique_info(InjectionTechnique.BOOLEAN_BASED)
        
        self.assertIsInstance(info, dict)
        self.assertIn('name', info)
        self.assertIn('description', info)
        self.assertIn('speed', info)
        self.assertIn('stealth', info)
        self.assertIn('reliability', info)
        
        self.assertEqual(info['name'], 'Boolean-based Blind')
    
    def test_technique_info_all_techniques(self):
        """Test that all techniques have information available."""
        techniques = [
            InjectionTechnique.BOOLEAN_BASED,
            InjectionTechnique.ERROR_BASED,
            InjectionTechnique.TIME_BASED,
            InjectionTechnique.UNION_BASED,
            InjectionTechnique.STACKED_QUERIES
        ]
        
        for technique in techniques:
            info = self.engine.get_technique_info(technique)
            self.assertIsInstance(info, dict)
            self.assertIn('name', info)
            self.assertIn('description', info)

class TestPayloadCraftingIntegration(unittest.TestCase):
    """Integration tests for payload crafting with injection discovery."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.engine = PayloadCraftingEngine()
        
        # Create realistic injection points
        self.login_injection_point = InjectionPoint(
            name="username",
            value="admin",
            injection_type=InjectionPointType.POST_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/login",
            method="POST",
            location="POST parameter in login form"
        )
        
        self.search_injection_point = InjectionPoint(
            name="q",
            value="test search",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/search?q=test+search",
            location="GET parameter in search"
        )
        
        self.api_injection_point = InjectionPoint(
            name="user.id",
            value="123",
            injection_type=InjectionPointType.JSON_FIELD,
            parameter_type=ParameterType.NUMERIC,
            url="http://example.com/api/user",
            method="POST",
            location="JSON field in API request"
        )
    
    def test_login_form_payload_generation(self):
        """Test payload generation for login form injection."""
        payloads = self.engine.craft_payloads(
            injection_point=self.login_injection_point,
            max_payloads=15
        )
        
        self.assertGreater(len(payloads), 0)
        
        # Should include string-appropriate payloads
        payload_strings = [payload for payload, template in payloads]
        
        # Check for SQL injection characteristics
        has_quotes = any("'" in payload or '"' in payload for payload in payload_strings)
        has_boolean_logic = any("AND" in payload.upper() or "OR" in payload.upper() or "SELECT" in payload.upper()
                               for payload in payload_strings)
        
        # Should have some form of SQL injection indicators
        self.assertTrue(has_quotes or has_boolean_logic)
    
    def test_search_parameter_payload_generation(self):
        """Test payload generation for search parameter injection."""
        payloads = self.engine.craft_payloads(
            injection_point=self.search_injection_point,
            techniques=[InjectionTechnique.UNION_BASED, InjectionTechnique.ERROR_BASED],
            max_payloads=10
        )
        
        self.assertGreater(len(payloads), 0)
        
        # Should include requested techniques
        techniques_found = set()
        for payload, template in payloads:
            techniques_found.add(template.technique)
        
        # At least one of the requested techniques should be present
        requested_techniques = {InjectionTechnique.UNION_BASED, InjectionTechnique.ERROR_BASED}
        self.assertTrue(techniques_found.intersection(requested_techniques))
    
    def test_api_json_payload_generation(self):
        """Test payload generation for JSON API injection."""
        payloads = self.engine.craft_payloads(
            injection_point=self.api_injection_point,
            max_payloads=8
        )
        
        self.assertGreater(len(payloads), 0)
        
        # Should include numeric-appropriate payloads
        payload_strings = [payload for payload, template in payloads]
        
        # Numeric injections should have minimal quoting
        minimal_quotes = sum(1 for payload in payload_strings if "'" not in payload and '"' not in payload)
        self.assertGreater(minimal_quotes, 0)
    
    def test_payload_diversity_across_techniques(self):
        """Test that payloads cover diverse injection techniques."""
        payloads = self.engine.craft_payloads(
            injection_point=self.login_injection_point,
            max_payloads=20
        )
        
        # Collect all techniques used
        techniques_used = set()
        for payload, template in payloads:
            techniques_used.add(template.technique)
        
        # Should have multiple techniques
        self.assertGreaterEqual(len(techniques_used), 2)
        
        # Should include some common techniques
        common_techniques = {
            InjectionTechnique.BOOLEAN_BASED,
            InjectionTechnique.ERROR_BASED,
            InjectionTechnique.TIME_BASED
        }
        
        self.assertTrue(techniques_used.intersection(common_techniques))
    
    def test_payload_database_diversity(self):
        """Test that payloads cover multiple database types."""
        payloads = self.engine.craft_payloads(
            injection_point=self.login_injection_point,
            max_payloads=25
        )
        
        # Collect all database types targeted
        databases_used = set()
        for payload, template in payloads:
            databases_used.add(template.database)
        
        # Should target multiple database types
        self.assertGreaterEqual(len(databases_used), 2)
        
        # Should include MySQL (most common)
        self.assertIn(DatabaseType.MYSQL, databases_used)

if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2) 