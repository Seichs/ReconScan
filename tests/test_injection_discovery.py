"""
ReconScan Injection Point Discovery Tests

Comprehensive test suite for the injection point discovery module.
Tests all major functionality including parameter detection, classification,
and priority scoring across different attack surfaces.
"""

import pytest
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
from scanner.commands.scanning.injection_discovery import (
    InjectionPointDiscovery,
    InjectionPoint,
    DiscoveryResult,
    InjectionPointType,
    ParameterType
)

class TestInjectionPointDiscovery:
    """Test suite for InjectionPointDiscovery class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.discovery = InjectionPointDiscovery()
    
    def test_url_parameter_analysis(self):
        """Test analysis of URL query parameters."""
        test_url = "https://example.com/search?q=test&id=123&category=electronics&debug=true"
        
        injection_points = self.discovery._analyze_url_parameters(test_url)
        
        assert len(injection_points) == 4
        
        # Check each parameter
        point_names = [point.name for point in injection_points]
        assert 'q' in point_names
        assert 'id' in point_names
        assert 'category' in point_names
        assert 'debug' in point_names
        
        # Check parameter types
        id_point = next(p for p in injection_points if p.name == 'id')
        assert id_point.parameter_type == ParameterType.NUMERIC
        assert id_point.test_priority >= 7  # Should be high priority
        
        debug_point = next(p for p in injection_points if p.name == 'debug')
        assert debug_point.parameter_type == ParameterType.BOOLEAN
    
    def test_parameter_type_detection(self):
        """Test parameter type detection accuracy."""
        test_cases = [
            ("123", ParameterType.NUMERIC),
            ("test@example.com", ParameterType.EMAIL),
            ("https://example.com", ParameterType.URL),
            ("2023-12-01", ParameterType.DATE),
            ("true", ParameterType.BOOLEAN),
            ("SGVsbG8gV29ybGQ=", ParameterType.BASE64),
            ('{"key": "value"}', ParameterType.JSON_OBJECT),
            ("<xml>data</xml>", ParameterType.XML_DATA),
            ("regular string", ParameterType.STRING)
        ]
        
        for value, expected_type in test_cases:
            detected_type = self.discovery._detect_parameter_type(value)
            assert detected_type == expected_type, f"Failed for '{value}' - expected {expected_type}, got {detected_type}"
    
    def test_form_data_analysis(self):
        """Test analysis of form data."""
        form_data = {
            'username': 'admin',
            'password': 'secret',
            'user_id': '42',
            'preferences': ['dark_mode', 'notifications'],
            'metadata': '{"theme": "dark"}'
        }
        
        injection_points = self.discovery._analyze_form_data("https://example.com/login", form_data)
        
        assert len(injection_points) == 5  # 4 regular fields + 2 array items
        
        # Check priority scoring
        user_id_point = next(p for p in injection_points if p.name == 'user_id')
        assert user_id_point.test_priority >= 7  # High priority for user_id + numeric
        
        # Check required field detection
        username_point = next(p for p in injection_points if p.name == 'username')
        assert username_point.is_required == True
    
    def test_json_data_analysis(self):
        """Test analysis of JSON data structures."""
        json_data = {
            "user": {
                "id": 123,
                "name": "John Doe",
                "email": "john@example.com"
            },
            "preferences": {
                "theme": "dark",
                "notifications": True
            },
            "tags": ["admin", "user"]
        }
        
        injection_points = self.discovery._analyze_json_data("https://example.com/api", json_data)
        
        # Should find all leaf values
        assert len(injection_points) >= 6
        
        # Check nested path tracking
        id_point = next(p for p in injection_points if p.name == 'id')
        assert id_point.nested_path == 'user.id'
        assert id_point.parameter_type == ParameterType.NUMERIC
        
        # Check array handling
        array_points = [p for p in injection_points if p.array_index is not None]
        assert len(array_points) == 2  # Two array items
    
    def test_xml_data_analysis(self):
        """Test analysis of XML data structures."""
        xml_data = '''
        <user id="123" active="true">
            <name>John Doe</name>
            <email>john@example.com</email>
            <preferences>
                <theme>dark</theme>
                <notifications>true</notifications>
            </preferences>
        </user>
        '''
        
        injection_points = self.discovery._analyze_xml_data("https://example.com/api", xml_data)
        
        # Should find attributes and text content
        assert len(injection_points) >= 6
        
        # Check attribute detection
        id_attr = next((p for p in injection_points if p.name == 'id'), None)
        assert id_attr is not None
        assert id_attr.parameter_type == ParameterType.NUMERIC
        
        # Check nested path for XML
        theme_point = next((p for p in injection_points if p.name == 'theme'), None)
        assert theme_point is not None
        assert '/preferences/theme' in theme_point.nested_path
    
    def test_filtering_detection(self):
        """Test detection of input filtering."""
        test_cases = [
            ("&lt;script&gt;", True),   # HTML encoding
            ("It\'s a test", True),     # SQL escaping
            ("Line 1\\nLine 2", True),  # JavaScript escaping
            ("normal text", False),     # No filtering
            ("", False)                 # Empty string
        ]
        
        for value, expected_filtered in test_cases:
            is_filtered = self.discovery._detect_filtering(value)
            assert is_filtered == expected_filtered, f"Failed for '{value}'"
    
    def test_validation_hints_detection(self):
        """Test detection of validation hints."""
        test_cases = [
            ("email", "test@example.com", True),
            ("password", "secret123", True),
            ("phone", "123-456-7890", True),
            ("username", "admin", False),
            ("query", "search term", False)
        ]
        
        for name, value, expected_validation in test_cases:
            has_validation = self.discovery._detect_validation_hints(name, value)
            assert has_validation == expected_validation, f"Failed for '{name}'"
    
    def test_priority_calculation(self):
        """Test injection point priority calculation."""
        # High priority: numeric ID parameter
        high_priority_point = InjectionPoint(
            name="user_id",
            value="123",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="https://example.com"
        )
        assert high_priority_point.test_priority >= 8
        
        # Medium priority: string parameter
        medium_priority_point = InjectionPoint(
            name="search",
            value="test",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="https://example.com"
        )
        assert 5 <= medium_priority_point.test_priority <= 7
        
        # Lower priority: header parameter
        low_priority_point = InjectionPoint(
            name="User-Agent",
            value="Mozilla/5.0",
            injection_type=InjectionPointType.HEADER,
            parameter_type=ParameterType.STRING,
            url="https://example.com"
        )
        assert low_priority_point.test_priority <= 4
    
    def test_header_parameter_analysis(self):
        """Test analysis of HTTP headers."""
        custom_headers = {
            'X-API-Key': 'secret123',
            'X-User-Token': 'token456'
        }
        
        injection_points = self.discovery._analyze_header_parameters(
            "https://example.com", 
            custom_headers
        )
        
        # Should include both standard testable headers and custom headers
        assert len(injection_points) >= 2
        
        # Check custom header detection
        api_key_point = next((p for p in injection_points if p.name == 'X-API-Key'), None)
        assert api_key_point is not None
        assert api_key_point.value == 'secret123'
        assert api_key_point.injection_type == InjectionPointType.HEADER

    @pytest.mark.asyncio
    async def test_comprehensive_discovery(self):
        """Test comprehensive injection point discovery."""
        # Mock the session and HTTP response
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='''
        <html>
        <body>
            <form method="post">
                <input name="username" value="admin">
                <input name="password" type="password">
                <select name="role">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
                <textarea name="comments">Default comment</textarea>
            </form>
        </body>
        </html>
        ''')
        mock_response.cookies = []
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        discovery = InjectionPointDiscovery(session=mock_session)
        
        # Test URL with query parameters
        target_url = "https://example.com/test?id=123&search=test"
        
        # Test with additional POST data
        additional_data = {"user_id": "456", "action": "login"}
        
        result = await discovery.discover_injection_points(
            target_url,
            additional_data=additional_data,
            include_forms=True,
            include_headers=True,
            include_cookies=False
        )
        
        # Verify results
        assert isinstance(result, DiscoveryResult)
        assert result.target_url == target_url
        assert result.total_parameters > 0
        assert len(result.injection_points) > 0
        
        # Check different types of injection points were found
        point_types = {point.injection_type for point in result.injection_points}
        assert InjectionPointType.QUERY_PARAMETER in point_types
        assert InjectionPointType.FORM_FIELD in point_types
        assert InjectionPointType.HEADER in point_types
        
        # Check priority points
        priority_points = result.get_priority_points(min_priority=7)
        assert len(priority_points) > 0
        
        # Verify points are sorted by priority
        priorities = [point.test_priority for point in result.injection_points]
        assert priorities == sorted(priorities, reverse=True)
    
    def test_url_validation(self):
        """Test URL validation."""
        valid_urls = [
            "https://example.com",
            "http://test.org/path",
            "https://sub.example.com:8080/path?param=value"
        ]
        
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",  # Valid but not HTTP(S)
            "",
            None
        ]
        
        for url in valid_urls:
            assert self.discovery._validate_url(url) == True, f"Should be valid: {url}"
        
        for url in invalid_urls:
            # Handle None case
            if url is None:
                continue
            assert self.discovery._validate_url(url) == False, f"Should be invalid: {url}"
    
    def test_discovery_result_methods(self):
        """Test DiscoveryResult helper methods."""
        # Create sample injection points
        points = [
            InjectionPoint(
                name="id", value="123", 
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.NUMERIC,
                url="https://example.com",
                test_priority=9
            ),
            InjectionPoint(
                name="search", value="test",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.STRING,
                url="https://example.com",
                test_priority=6
            ),
            InjectionPoint(
                name="User-Agent", value="Mozilla",
                injection_type=InjectionPointType.HEADER,
                parameter_type=ParameterType.STRING,
                url="https://example.com",
                test_priority=3
            )
        ]
        
        result = DiscoveryResult(
            target_url="https://example.com",
            injection_points=points,
            total_parameters=3
        )
        
        # Test priority filtering
        high_priority = result.get_priority_points(min_priority=7)
        assert len(high_priority) == 1
        assert high_priority[0].name == "id"
        
        # Test type filtering
        query_points = result.get_points_by_type(InjectionPointType.QUERY_PARAMETER)
        assert len(query_points) == 2
        
        header_points = result.get_points_by_type(InjectionPointType.HEADER)
        assert len(header_points) == 1
    
    def test_analysis_notes_generation(self):
        """Test automatic analysis notes generation."""
        # Numeric parameter should get specific note
        numeric_point = InjectionPoint(
            name="id", value="123",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="https://example.com"
        )
        assert any("SQL injection potential" in note for note in numeric_point.notes)
        
        # Filtered parameter should get filtering note
        filtered_point = InjectionPoint(
            name="test", value="&lt;script&gt;",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="https://example.com",
            appears_filtered=True
        )
        assert any("filtering detected" in note for note in filtered_point.notes)
    
    @pytest.mark.asyncio
    async def test_post_data_analysis_edge_cases(self):
        """Test POST data analysis with various edge cases."""
        discovery = InjectionPointDiscovery()
        url = "https://example.com/api"
        
        # Test with bytes data
        bytes_data = b'{"user": "admin", "pass": "secret"}'
        points = await discovery._analyze_post_data(url, bytes_data)
        assert len(points) >= 2
        
        # Test with malformed JSON
        malformed_json = '{"incomplete": "json"'
        points = await discovery._analyze_post_data(url, malformed_json)
        assert len(points) >= 1  # Should treat as raw data
        
        # Test with URL-encoded data
        urlencoded_data = "username=admin&password=secret&remember=true"
        points = await discovery._analyze_post_data(url, urlencoded_data)
        assert len(points) == 3
        
        # Test with empty data
        empty_data = ""
        points = await discovery._analyze_post_data(url, empty_data)
        assert len(points) >= 1  # Should create raw data point
    
    def test_html_form_parsing(self):
        """Test HTML form parsing with complex forms."""
        html_content = '''
        <html>
        <body>
            <form method="post" action="/login">
                <input type="text" name="username" value="admin" required>
                <input type="password" name="password" placeholder="Enter password">
                <input type="email" name="email" value="test@example.com">
                <input type="hidden" name="csrf_token" value="abc123">
                <select name="role">
                    <option value="user" selected>User</option>
                    <option value="admin">Administrator</option>
                </select>
                <textarea name="description">Default description</textarea>
                <input type="submit" value="Login">
            </form>
            
            <form method="get" action="/search">
                <input type="search" name="q" placeholder="Search...">
                <input type="submit" value="Search">
            </form>
        </body>
        </html>
        '''
        
        forms = self.discovery._parse_html_forms(html_content)
        assert len(forms) == 2
        
        # Check first form (login)
        login_form = forms[0]
        field_names = [field['name'] for field in login_form['fields']]
        assert 'username' in field_names
        assert 'password' in field_names
        assert 'email' in field_names
        assert 'csrf_token' in field_names
        assert 'role' in field_names
        assert 'description' in field_names
        
        # Check field values
        username_field = next(f for f in login_form['fields'] if f['name'] == 'username')
        assert username_field['value'] == 'admin'
        
        # Check second form (search)
        search_form = forms[1]
        search_field_names = [field['name'] for field in search_form['fields']]
        assert 'q' in search_field_names

# Integration test for the complete workflow
class TestInjectionDiscoveryIntegration:
    """Integration tests for the complete injection discovery workflow."""
    
    @pytest.mark.asyncio
    async def test_complete_workflow(self):
        """Test the complete injection discovery workflow."""
        # This test would require actual HTTP requests in a real scenario
        # For now, we'll test the core workflow with mocked responses
        
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='''
        <html>
        <body>
            <form method="post">
                <input name="id" value="123">
                <input name="search" value="test query">
                <input name="email" value="user@example.com">
            </form>
        </body>
        </html>
        ''')
        mock_response.cookies = []
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        discovery = InjectionPointDiscovery(session=mock_session)
        
        # Test comprehensive discovery
        result = await discovery.discover_injection_points(
            "https://example.com/app?page=1&category=electronics",
            additional_data={"user_id": "456", "action": "update"},
            include_forms=True,
            include_headers=True,
            include_cookies=False
        )
        
        # Verify comprehensive results
        assert result.total_parameters > 0
        assert result.high_priority_points > 0
        assert result.discovery_time > 0
        
        # Should have found injection points from multiple sources
        point_types = {point.injection_type for point in result.injection_points}
        expected_types = {
            InjectionPointType.QUERY_PARAMETER,
            InjectionPointType.FORM_FIELD,
            InjectionPointType.HEADER
        }
        assert expected_types.issubset(point_types)
        
        # Verify priority ranking
        priorities = [point.test_priority for point in result.injection_points]
        assert priorities == sorted(priorities, reverse=True)
        
        # Check that high-priority points come first
        high_priority_points = result.get_priority_points(min_priority=7)
        if high_priority_points:
            assert result.injection_points[0].test_priority >= 7

if __name__ == "__main__":
    # Run basic tests
    import sys
    
    # Test parameter type detection
    discovery = InjectionPointDiscovery()
    
    print("Testing parameter type detection...")
    test_values = [
        ("123", ParameterType.NUMERIC),
        ("test@example.com", ParameterType.EMAIL),
        ("https://example.com", ParameterType.URL),
        ("true", ParameterType.BOOLEAN),
        ("regular text", ParameterType.STRING)
    ]
    
    for value, expected in test_values:
        detected = discovery._detect_parameter_type(value)
        status = "✓" if detected == expected else "✗"
        print(f"  {status} '{value}' -> {detected.value}")
    
    print("\nTesting URL parameter analysis...")
    test_url = "https://example.com/search?q=test&id=123&debug=true"
    points = discovery._analyze_url_parameters(test_url)
    print(f"  Found {len(points)} injection points:")
    for point in points:
        print(f"    - {point.name}: {point.parameter_type.value} (priority: {point.test_priority})")
    
    print("\nTesting form data analysis...")
    form_data = {"username": "admin", "user_id": "42", "active": "true"}
    points = discovery._analyze_form_data("https://example.com", form_data)
    print(f"  Found {len(points)} injection points:")
    for point in points:
        print(f"    - {point.name}: {point.parameter_type.value} (priority: {point.test_priority})")
    
    print("\nBasic tests completed successfully!")