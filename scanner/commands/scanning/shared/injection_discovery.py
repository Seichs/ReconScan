"""
ReconScan Injection Point Discovery Module

Professional injection point discovery system for identifying potential SQL injection
attack surfaces across web applications. Supports comprehensive parameter analysis
for GET/POST parameters, HTTP headers, cookies, and complex data structures.

This module serves as the foundation for advanced SQL injection testing by providing
structured injection point identification with context awareness and intelligent
parameter classification.

Author: ReconScan Security Framework
Version: 1.0.0
"""

import re
import json
import asyncio
import aiohttp
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, parse_qsl, unquote
from pathlib import Path
import html
import xml.etree.ElementTree as ET
from enum import Enum

class InjectionPointType(Enum):
    """Enumeration of injection point types for systematic testing."""
    QUERY_PARAMETER = "query_param"
    POST_PARAMETER = "post_param"
    HEADER = "header"
    COOKIE = "cookie"
    PATH_PARAMETER = "path_param"
    JSON_FIELD = "json_field"
    XML_ATTRIBUTE = "xml_attr"
    FORM_FIELD = "form_field"
    FRAGMENT = "fragment"

class ParameterType(Enum):
    """Parameter data type classification for context-aware testing."""
    NUMERIC = "numeric"
    STRING = "string"
    BOOLEAN = "boolean"
    ARRAY = "array"
    JSON_OBJECT = "json"
    XML_DATA = "xml"
    BASE64 = "base64"
    EMAIL = "email"
    URL = "url"
    DATE = "date"
    UNKNOWN = "unknown"

@dataclass
class InjectionPoint:
    """
    Represents a potential injection point with comprehensive metadata.
    
    This class encapsulates all information needed for intelligent payload
    generation and vulnerability testing, including parameter context,
    data type analysis, and security-relevant characteristics.
    """
    
    # Core identification
    name: str                           # Parameter/field name
    value: str                          # Original parameter value
    injection_type: InjectionPointType  # Type of injection point
    parameter_type: ParameterType       # Data type classification
    
    # Location context
    url: str                           # Full URL where parameter was found
    method: str = "GET"                # HTTP method (GET, POST, etc.)
    location: str = ""                 # Specific location (query, body, etc.)
    
    # Parameter analysis
    is_required: bool = False          # Whether parameter appears required
    has_validation: bool = False       # Signs of client-side validation
    is_encoded: bool = False           # Whether value appears encoded
    encoding_type: Optional[str] = None # Type of encoding detected
    
    # Security context
    appears_filtered: bool = False     # Signs of input filtering
    charset_restricted: bool = False   # Limited character set detected
    length_restricted: bool = False    # Length limitations detected
    max_length: Optional[int] = None   # Maximum detected length
    
    # Structural information for complex parameters
    parent_structure: Optional[str] = None  # Parent JSON/XML structure
    nested_path: Optional[str] = None       # Path within nested structure
    array_index: Optional[int] = None       # Index if part of array
    
    # Testing metadata
    test_priority: int = 5             # Priority score (1-10, 10=highest)
    confidence: float = 1.0            # Confidence this is injectable (0.0-1.0)
    notes: List[str] = field(default_factory=list)  # Analysis notes
    
    def __post_init__(self):
        """Post-initialization processing for derived attributes."""
        # Calculate test priority based on characteristics
        self._calculate_test_priority()
        
        # Add automatic analysis notes
        self._generate_analysis_notes()
    
    def _calculate_test_priority(self):
        """Calculate testing priority based on parameter characteristics."""
        priority = 5  # Base priority
        
        # Higher priority for numeric parameters (common SQL injection targets)
        if self.parameter_type == ParameterType.NUMERIC:
            priority += 2
        
        # Higher priority for common vulnerable parameter names
        vulnerable_names = {
            'id', 'user_id', 'product_id', 'page_id', 'cat_id', 'category',
            'search', 'q', 'query', 'keyword', 'user', 'username', 'login',
            'page', 'view', 'action', 'cmd', 'exec', 'file', 'path'
        }
        if self.name.lower() in vulnerable_names:
            priority += 2
        
        # Lower priority if filtering is detected
        if self.appears_filtered:
            priority -= 1
        
        # Higher priority for required parameters
        if self.is_required:
            priority += 1
        
        # Adjust for injection point type
        type_priorities = {
            InjectionPointType.QUERY_PARAMETER: 0,
            InjectionPointType.POST_PARAMETER: 1,
            InjectionPointType.FORM_FIELD: 1,
            InjectionPointType.COOKIE: -1,
            InjectionPointType.HEADER: -2,
            InjectionPointType.JSON_FIELD: 0,
            InjectionPointType.PATH_PARAMETER: 1
        }
        priority += type_priorities.get(self.injection_type, 0)
        
        # Ensure priority stays within bounds
        self.test_priority = max(1, min(10, priority))
    
    def _generate_analysis_notes(self):
        """Generate automatic analysis notes based on characteristics."""
        if self.parameter_type == ParameterType.NUMERIC:
            self.notes.append("Numeric parameter - high SQL injection potential")
        
        if self.appears_filtered:
            self.notes.append("Input filtering detected - may require evasion")
        
        if self.is_encoded:
            self.notes.append(f"Encoded parameter ({self.encoding_type}) - decode before testing")
        
        if self.has_validation:
            self.notes.append("Client-side validation detected")
        
        if self.length_restricted and self.max_length:
            self.notes.append(f"Length restricted to {self.max_length} characters")

@dataclass
class DiscoveryResult:
    """Results of injection point discovery analysis."""
    
    target_url: str
    injection_points: List[InjectionPoint] = field(default_factory=list)
    total_parameters: int = 0
    high_priority_points: int = 0
    discovery_time: float = 0.0
    forms_discovered: int = 0
    cookies_analyzed: int = 0
    headers_analyzed: int = 0
    errors_encountered: List[str] = field(default_factory=list)
    
    def get_priority_points(self, min_priority: int = 7) -> List[InjectionPoint]:
        """Get injection points above specified priority threshold."""
        return [point for point in self.injection_points if point.test_priority >= min_priority]
    
    def get_points_by_type(self, point_type: InjectionPointType) -> List[InjectionPoint]:
        """Get injection points of specified type."""
        return [point for point in self.injection_points if point.injection_type == point_type]

class InjectionPointDiscovery:
    """
    Professional injection point discovery engine for SQL injection testing.
    
    This class implements comprehensive injection point identification across
    all potential attack surfaces of web applications, including:
    
    - URL query parameters
    - POST form data (application/x-www-form-urlencoded)
    - JSON request bodies
    - XML request bodies
    - HTTP headers (standard and custom)
    - Cookies
    - Path parameters
    - Complex nested structures
    
    Features:
    - Intelligent parameter type detection
    - Context-aware analysis
    - Security characteristic identification
    - Priority-based ranking for efficient testing
    - Comprehensive metadata collection
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """
        Initialize injection point discovery engine.
        
        Args:
            session: Optional aiohttp session for HTTP requests
        """
        self.session = session
        self._should_close_session = session is None
        
        # Parameter type detection patterns
        self.type_patterns = {
            ParameterType.NUMERIC: [
                r'^\d+$',                           # Pure numeric
                r'^\d+\.\d+$',                      # Decimal
                r'^-?\d+$',                         # Signed integer
                r'^\d{1,3}(,\d{3})*$'              # Comma-separated numbers
            ],
            ParameterType.EMAIL: [
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            ],
            ParameterType.URL: [
                r'^https?://[^\s/$.?#].[^\s]*$',    # HTTP URLs
                r'^[a-zA-Z][a-zA-Z\d+.-]*://[^\s]*$'  # Other schemes
            ],
            ParameterType.DATE: [
                r'^\d{4}-\d{2}-\d{2}$',             # YYYY-MM-DD
                r'^\d{2}/\d{2}/\d{4}$',             # MM/DD/YYYY
                r'^\d{2}-\d{2}-\d{4}$'              # MM-DD-YYYY
            ],
            ParameterType.BASE64: [
                r'^[A-Za-z0-9+/]*={0,2}$'          # Base64 pattern
            ],
            ParameterType.BOOLEAN: [
                r'^(true|false)$',                  # Boolean literals
                r'^(0|1)$',                         # Binary boolean
                r'^(yes|no)$',                      # Text boolean
                r'^(on|off)$'                       # Switch boolean
            ]
        }
        
        # Common vulnerable parameter names for priority scoring
        self.vulnerable_parameter_names = {
            'id', 'user_id', 'product_id', 'item_id', 'post_id', 'page_id',
            'cat_id', 'category_id', 'tag_id', 'album_id', 'photo_id',
            'search', 'q', 'query', 'keyword', 'term', 'find',
            'user', 'username', 'login', 'email', 'account',
            'page', 'view', 'action', 'cmd', 'command', 'exec',
            'file', 'path', 'dir', 'folder', 'document',
            'sort', 'order', 'filter', 'limit', 'offset',
            'lang', 'language', 'locale', 'country', 'region'
        }
        
        # Headers commonly tested for injection
        self.testable_headers = {
            'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
            'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr',
            'X-Client-IP', 'CF-Connecting-IP', 'True-Client-IP',
            'Accept-Language', 'Accept-Encoding', 'Accept-Charset',
            'Cache-Control', 'X-Requested-With', 'X-CSRF-Token',
            'Authorization', 'Cookie'
        }
        
        # TODO: Implement machine learning for parameter importance prediction
        # TODO: Add support for GraphQL injection point discovery
        # TODO: Implement WebSocket parameter analysis
        # FIXME: Handle edge cases in deeply nested JSON structures
        
    async def discover_injection_points(self, target_url: str, 
                                      additional_data: Optional[Dict[str, Any]] = None,
                                      include_forms: bool = True,
                                      include_headers: bool = True,
                                      include_cookies: bool = True,
                                      custom_headers: Optional[Dict[str, str]] = None) -> DiscoveryResult:
        """
        Comprehensive injection point discovery for a target URL.
        
        This method performs complete analysis of potential injection points
        across all attack surfaces, including dynamic form discovery and
        intelligent parameter classification.
        
        Args:
            target_url: Target URL to analyze
            additional_data: Optional POST data or JSON payload to analyze
            include_forms: Whether to discover and analyze forms
            include_headers: Whether to analyze HTTP headers
            include_cookies: Whether to analyze cookies
            custom_headers: Optional custom headers to include in analysis
            
        Returns:
            DiscoveryResult: Comprehensive analysis results
            
        Raises:
            ValueError: If target URL is invalid
            aiohttp.ClientError: If HTTP request fails
        """
        start_time = asyncio.get_event_loop().time()
        
        # Validate target URL
        if not self._validate_url(target_url):
            raise ValueError(f"Invalid target URL: {target_url}")
        
        # Initialize result object
        result = DiscoveryResult(target_url=target_url)
        
        try:
            # Create session if not provided
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            # Step 1: Analyze URL query parameters
            query_points = self._analyze_url_parameters(target_url)
            result.injection_points.extend(query_points)
            
            # Step 2: Analyze additional POST data if provided
            if additional_data:
                post_points = await self._analyze_post_data(target_url, additional_data)
                result.injection_points.extend(post_points)
            
            # Step 3: Discover and analyze forms if requested
            if include_forms:
                try:
                    form_points = await self._discover_form_parameters(target_url)
                    result.injection_points.extend(form_points)
                    result.forms_discovered = len(form_points)
                except Exception as e:
                    result.errors_encountered.append(f"Form discovery error: {str(e)}")
            
            # Step 4: Analyze headers if requested
            if include_headers:
                header_points = self._analyze_header_parameters(target_url, custom_headers)
                result.injection_points.extend(header_points)
                result.headers_analyzed = len(header_points)
            
            # Step 5: Analyze cookies if requested
            if include_cookies:
                try:
                    cookie_points = await self._analyze_cookie_parameters(target_url)
                    result.injection_points.extend(cookie_points)
                    result.cookies_analyzed = len(cookie_points)
                except Exception as e:
                    result.errors_encountered.append(f"Cookie analysis error: {str(e)}")
            
            # Step 6: Post-process results
            result.total_parameters = len(result.injection_points)
            result.high_priority_points = len(result.get_priority_points())
            result.discovery_time = asyncio.get_event_loop().time() - start_time
            
            # Sort injection points by priority (highest first)
            result.injection_points.sort(key=lambda x: x.test_priority, reverse=True)
            
            return result
            
        finally:
            # Clean up session if we created it
            if self._should_close_session and self.session:
                await self.session.close()
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format and accessibility."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    def _analyze_url_parameters(self, url: str) -> List[InjectionPoint]:
        """
        Analyze URL query parameters for injection points.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            List of discovered injection points from query parameters
        """
        injection_points = []
        
        try:
            parsed_url = urlparse(url)
            
            if not parsed_url.query:
                return injection_points
            
            # Parse query parameters
            params = parse_qsl(parsed_url.query, keep_blank_values=True)
            
            for param_name, param_value in params:
                # Decode URL-encoded parameters
                decoded_name = unquote(param_name)
                decoded_value = unquote(param_value)
                
                # Detect parameter characteristics
                param_type = self._detect_parameter_type(decoded_value)
                is_encoded = param_value != decoded_value
                encoding_type = "url" if is_encoded else None
                
                # Create injection point
                injection_point = InjectionPoint(
                    name=decoded_name,
                    value=decoded_value,
                    injection_type=InjectionPointType.QUERY_PARAMETER,
                    parameter_type=param_type,
                    url=url,
                    method="GET",
                    location="query_string",
                    is_encoded=is_encoded,
                    encoding_type=encoding_type,
                    appears_filtered=self._detect_filtering(decoded_value),
                    has_validation=self._detect_validation_hints(decoded_name, decoded_value)
                )
                
                injection_points.append(injection_point)
                
        except Exception as e:
            # Log error but don't fail completely
            pass
        
        return injection_points
    
    async def _analyze_post_data(self, url: str, data: Union[Dict, str, bytes]) -> List[InjectionPoint]:
        """
        Analyze POST data for injection points.
        
        Args:
            url: Target URL
            data: POST data (form data, JSON, XML, or raw)
            
        Returns:
            List of discovered injection points from POST data
        """
        injection_points = []
        
        try:
            if isinstance(data, dict):
                # Standard form data
                injection_points.extend(self._analyze_form_data(url, data))
            elif isinstance(data, str):
                # Detect data type and parse accordingly
                data = data.strip()
                
                if data.startswith('{') and data.endswith('}'):
                    # JSON data
                    try:
                        json_data = json.loads(data)
                        injection_points.extend(self._analyze_json_data(url, json_data))
                    except json.JSONDecodeError:
                        # Treat as raw string data
                        injection_points.extend(self._analyze_raw_data(url, data))
                
                elif data.startswith('<') and data.endswith('>'):
                    # XML data
                    injection_points.extend(self._analyze_xml_data(url, data))
                
                elif '=' in data and ('&' in data or data.count('=') == 1):
                    # URL-encoded form data
                    form_data = dict(parse_qsl(data, keep_blank_values=True))
                    injection_points.extend(self._analyze_form_data(url, form_data))
                
                else:
                    # Raw data
                    injection_points.extend(self._analyze_raw_data(url, data))
            
            elif isinstance(data, bytes):
                # Convert bytes to string and reanalyze
                try:
                    string_data = data.decode('utf-8')
                    return await self._analyze_post_data(url, string_data)
                except UnicodeDecodeError:
                    # Handle as binary data
                    injection_points.extend(self._analyze_raw_data(url, data.hex()))
        
        except Exception as e:
            # Log error but continue
            pass
        
        return injection_points
    
    def _analyze_form_data(self, url: str, form_data: Dict[str, Any]) -> List[InjectionPoint]:
        """Analyze form data dictionary for injection points."""
        injection_points = []
        
        for field_name, field_value in form_data.items():
            if isinstance(field_value, (list, tuple)):
                # Handle multi-value fields
                for i, value in enumerate(field_value):
                    injection_point = self._create_form_injection_point(
                        url, f"{field_name}[{i}]", str(value)
                    )
                    injection_point.array_index = i
                    injection_points.append(injection_point)
            else:
                injection_point = self._create_form_injection_point(
                    url, field_name, str(field_value)
                )
                injection_points.append(injection_point)
        
        return injection_points
    
    def _create_form_injection_point(self, url: str, name: str, value: str) -> InjectionPoint:
        """Create injection point for form field."""
        param_type = self._detect_parameter_type(value)
        
        return InjectionPoint(
            name=name,
            value=value,
            injection_type=InjectionPointType.FORM_FIELD,
            parameter_type=param_type,
            url=url,
            method="POST",
            location="form_data",
            appears_filtered=self._detect_filtering(value),
            has_validation=self._detect_validation_hints(name, value),
            is_required=self._is_likely_required_field(name)
        )
    
    def _analyze_json_data(self, url: str, json_data: Dict[str, Any], 
                          parent_path: str = "") -> List[InjectionPoint]:
        """Recursively analyze JSON data for injection points."""
        injection_points = []
        
        def analyze_json_recursive(data: Any, path: str = ""):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    if isinstance(value, (dict, list)):
                        analyze_json_recursive(value, current_path)
                    else:
                        # Create injection point for leaf values
                        injection_point = InjectionPoint(
                            name=key,
                            value=str(value),
                            injection_type=InjectionPointType.JSON_FIELD,
                            parameter_type=self._detect_parameter_type(str(value)),
                            url=url,
                            method="POST",
                            location="json_body",
                            parent_structure="json",
                            nested_path=current_path,
                            appears_filtered=self._detect_filtering(str(value))
                        )
                        injection_points.append(injection_point)
            
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    
                    if isinstance(item, (dict, list)):
                        analyze_json_recursive(item, current_path)
                    else:
                        # Create injection point for array values
                        injection_point = InjectionPoint(
                            name=f"array_item_{i}",
                            value=str(item),
                            injection_type=InjectionPointType.JSON_FIELD,
                            parameter_type=self._detect_parameter_type(str(item)),
                            url=url,
                            method="POST",
                            location="json_body",
                            parent_structure="json",
                            nested_path=current_path,
                            array_index=i
                        )
                        injection_points.append(injection_point)
        
        analyze_json_recursive(json_data, parent_path)
        return injection_points
    
    def _analyze_xml_data(self, url: str, xml_data: str) -> List[InjectionPoint]:
        """Analyze XML data for injection points."""
        injection_points = []
        
        try:
            root = ET.fromstring(xml_data)
            
            def analyze_xml_recursive(element: ET.Element, path: str = ""):
                current_path = f"{path}/{element.tag}" if path else element.tag
                
                # Analyze element text
                if element.text and element.text.strip():
                    injection_point = InjectionPoint(
                        name=element.tag,
                        value=element.text.strip(),
                        injection_type=InjectionPointType.XML_ATTRIBUTE,
                        parameter_type=self._detect_parameter_type(element.text.strip()),
                        url=url,
                        method="POST",
                        location="xml_body",
                        parent_structure="xml",
                        nested_path=current_path
                    )
                    injection_points.append(injection_point)
                
                # Analyze attributes
                for attr_name, attr_value in element.attrib.items():
                    injection_point = InjectionPoint(
                        name=attr_name,
                        value=attr_value,
                        injection_type=InjectionPointType.XML_ATTRIBUTE,
                        parameter_type=self._detect_parameter_type(attr_value),
                        url=url,
                        method="POST",
                        location="xml_body",
                        parent_structure="xml",
                        nested_path=f"{current_path}@{attr_name}"
                    )
                    injection_points.append(injection_point)
                
                # Recursively analyze child elements
                for child in element:
                    analyze_xml_recursive(child, current_path)
            
            analyze_xml_recursive(root)
            
        except ET.ParseError:
            # If XML parsing fails, treat as raw data
            pass
        
        return injection_points
    
    def _analyze_raw_data(self, url: str, raw_data: Union[str, bytes]) -> List[InjectionPoint]:
        """Analyze raw data for potential injection points."""
        injection_points = []
        
        # Convert bytes to string if necessary
        if isinstance(raw_data, bytes):
            try:
                raw_data = raw_data.decode('utf-8')
            except UnicodeDecodeError:
                raw_data = raw_data.hex()
        
        # Create a single injection point for raw data
        injection_point = InjectionPoint(
            name="raw_data",
            value=str(raw_data),
            injection_type=InjectionPointType.POST_PARAMETER,
            parameter_type=self._detect_parameter_type(str(raw_data)),
            url=url,
            method="POST",
            location="raw_body",
            test_priority=3  # Lower priority for raw data
        )
        injection_points.append(injection_point)
        
        return injection_points
    
    async def _discover_form_parameters(self, url: str) -> List[InjectionPoint]:
        """
        Discover form parameters by fetching and parsing the target URL.
        
        Args:
            url: Target URL to fetch and analyze for forms
            
        Returns:
            List of injection points discovered in forms
        """
        injection_points = []
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    content = await response.text()
                    forms = self._parse_html_forms(content)
                    
                    for form in forms:
                        form_points = self._analyze_html_form(url, form)
                        injection_points.extend(form_points)
        
        except asyncio.TimeoutError:
            pass  # Skip if timeout
        except Exception:
            pass  # Skip if any other error
        
        return injection_points
    
    def _parse_html_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Parse HTML content to extract form information.
        
        Args:
            html_content: HTML content to parse
            
        Returns:
            List of form dictionaries with fields and attributes
        """
        forms = []
        
        # Simple regex-based form parsing (could be enhanced with proper HTML parser)
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*(?:name=["\']([^"\']*)["\'])[^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>'
        select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>(.*?)</select>'
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>(.*?)</textarea>'
        
        form_matches = re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for form_match in form_matches:
            form_content = form_match.group(1)
            form_fields = []
            
            # Extract input fields
            input_matches = re.finditer(input_pattern, form_content, re.IGNORECASE)
            for input_match in input_matches:
                field_name = input_match.group(1)
                field_value = input_match.group(2) or ""
                form_fields.append({
                    'name': field_name,
                    'value': field_value,
                    'type': 'input'
                })
            
            # Extract select fields
            select_matches = re.finditer(select_pattern, form_content, re.DOTALL | re.IGNORECASE)
            for select_match in select_matches:
                field_name = select_match.group(1)
                # Extract first option value as default
                option_pattern = r'<option[^>]*value=["\']([^"\']*)["\']'
                option_match = re.search(option_pattern, select_match.group(2), re.IGNORECASE)
                field_value = option_match.group(1) if option_match else ""
                form_fields.append({
                    'name': field_name,
                    'value': field_value,
                    'type': 'select'
                })
            
            # Extract textarea fields
            textarea_matches = re.finditer(textarea_pattern, form_content, re.DOTALL | re.IGNORECASE)
            for textarea_match in textarea_matches:
                field_name = textarea_match.group(1)
                field_value = textarea_match.group(2).strip()
                form_fields.append({
                    'name': field_name,
                    'value': field_value,
                    'type': 'textarea'
                })
            
            if form_fields:
                forms.append({'fields': form_fields})
        
        return forms
    
    def _analyze_html_form(self, url: str, form: Dict[str, Any]) -> List[InjectionPoint]:
        """Analyze a parsed HTML form for injection points."""
        injection_points = []
        
        for field in form.get('fields', []):
            field_name = field.get('name', '')
            field_value = field.get('value', '')
            field_type = field.get('type', 'input')
            
            if field_name:  # Only process fields with names
                injection_point = InjectionPoint(
                    name=field_name,
                    value=field_value,
                    injection_type=InjectionPointType.FORM_FIELD,
                    parameter_type=self._detect_parameter_type(field_value),
                    url=url,
                    method="POST",
                    location=f"html_form_{field_type}",
                    is_required=self._is_likely_required_field(field_name),
                    has_validation=self._detect_validation_hints(field_name, field_value)
                )
                injection_points.append(injection_point)
        
        return injection_points
    
    def _analyze_header_parameters(self, url: str, 
                                 custom_headers: Optional[Dict[str, str]] = None) -> List[InjectionPoint]:
        """Analyze HTTP headers for injection points."""
        injection_points = []
        
        # Standard testable headers
        for header_name in self.testable_headers:
            injection_point = InjectionPoint(
                name=header_name,
                value="",  # Headers don't have default values
                injection_type=InjectionPointType.HEADER,
                parameter_type=ParameterType.STRING,
                url=url,
                method="GET",
                location="http_headers",
                test_priority=4  # Lower priority than parameters
            )
            injection_points.append(injection_point)
        
        # Custom headers if provided
        if custom_headers:
            for header_name, header_value in custom_headers.items():
                injection_point = InjectionPoint(
                    name=header_name,
                    value=header_value,
                    injection_type=InjectionPointType.HEADER,
                    parameter_type=self._detect_parameter_type(header_value),
                    url=url,
                    method="GET",
                    location="custom_headers"
                )
                injection_points.append(injection_point)
        
        return injection_points
    
    async def _analyze_cookie_parameters(self, url: str) -> List[InjectionPoint]:
        """Analyze cookies for injection points."""
        injection_points = []
        
        try:
            # Make a request to get cookies
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.cookies:
                    for cookie in response.cookies.values():
                        injection_point = InjectionPoint(
                            name=cookie.key,
                            value=cookie.value,
                            injection_type=InjectionPointType.COOKIE,
                            parameter_type=self._detect_parameter_type(cookie.value),
                            url=url,
                            method="GET",
                            location="cookies",
                            test_priority=3  # Lower priority than parameters
                        )
                        injection_points.append(injection_point)
        
        except Exception:
            pass  # Skip if cookie analysis fails
        
        return injection_points
    
    def _detect_parameter_type(self, value: str) -> ParameterType:
        """
        Detect parameter data type based on value patterns.
        
        Args:
            value: Parameter value to analyze
            
        Returns:
            Detected parameter type
        """
        if not value or not isinstance(value, str):
            return ParameterType.UNKNOWN
        
        value = value.strip()
        
        # Check against each type pattern
        for param_type, patterns in self.type_patterns.items():
            if any(re.match(pattern, value, re.IGNORECASE) for pattern in patterns):
                return param_type
        
        # Special cases
        if value.startswith('{') and value.endswith('}'):
            try:
                json.loads(value)
                return ParameterType.JSON_OBJECT
            except json.JSONDecodeError:
                pass
        
        if value.startswith('<') and value.endswith('>'):
            return ParameterType.XML_DATA
        
        if isinstance(value, str) and len(value) > 20 and value.isalnum():
            # Potential Base64 or hash
            return ParameterType.BASE64
        
        # Default to string type
        return ParameterType.STRING
    
    def _detect_filtering(self, value: str) -> bool:
        """
        Detect signs of input filtering or sanitization.
        
        Args:
            value: Parameter value to analyze
            
        Returns:
            True if filtering appears to be applied
        """
        if not value:
            return False
        
        # Signs of HTML entity encoding
        if any(entity in value for entity in ['&lt;', '&gt;', '&amp;', '&quot;', '&#']):
            return True
        
        # Signs of SQL character escaping
        if any(escaped in value for escaped in ["\\'", '\\"', "\\%", "\\_"]):
            return True
        
        # Signs of JavaScript escaping
        if any(escaped in value for escaped in ['\\n', '\\r', '\\t', '\\\\', '\\/']):
            return True
        
        return False
    
    def _detect_validation_hints(self, name: str, value: str) -> bool:
        """
        Detect hints of client-side validation.
        
        Args:
            name: Parameter name
            value: Parameter value
            
        Returns:
            True if validation hints are detected
        """
        # Parameter names that commonly have validation
        validated_names = {
            'email', 'phone', 'zip', 'postal', 'credit', 'card',
            'ssn', 'social', 'password', 'confirm', 'captcha'
        }
        
        name_lower = name.lower()
        return any(validated_name in name_lower for validated_name in validated_names)
    
    def _is_likely_required_field(self, name: str) -> bool:
        """
        Determine if a field is likely required based on naming patterns.
        
        Args:
            name: Field name to analyze
            
        Returns:
            True if field appears to be required
        """
        required_indicators = {
            'id', 'user_id', 'username', 'email', 'password',
            'required', 'mandatory', 'necessary'
        }
        
        name_lower = name.lower()
        return any(indicator in name_lower for indicator in required_indicators)

# Export main classes for external use
__all__ = [
    'InjectionPointDiscovery',
    'InjectionPoint', 
    'DiscoveryResult',
    'InjectionPointType',
    'ParameterType'
]