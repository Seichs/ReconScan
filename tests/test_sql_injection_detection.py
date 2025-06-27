"""
ReconScan SQL Injection Detection System Tests

Comprehensive test suite for the SQL injection detection, analysis, and exploitation system.
Tests all major components including payload integration, response analysis, validation,
and scanning modes.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import time

from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_injection_scanner import (
    SQLInjectionScanner,
    VulnerabilityFinding,
    DetectionTechnique,
    ScanMode,
    ScanConfiguration,
    DatabaseType
)
from scanner.commands.scanning.vulnerability_scanners.sql_injection.sql_payload_crafting_engine import (
    PayloadCraftingEngine,
    PayloadCraftingContext,
    InjectionTechnique,
    DatabaseType as CraftingDatabaseType
)
from scanner.commands.scanning.shared.injection_discovery import (
    InjectionPoint,
    InjectionPointType,
    ParameterType
)

class TestSQLInjectionScanner:
    """Test suite for SQL injection scanner core functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create SQL injection scanner instance for testing."""
        session = Mock(spec=aiohttp.ClientSession)
        return SQLInjectionScanner(session)
    
    @pytest.fixture
    def sample_injection_point(self):
        """Create sample injection point for testing."""
        return InjectionPoint(
            name="q",
            value="test",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/search",
            method="GET",
            test_priority=8
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner is not None
        assert isinstance(scanner.payload_engine, PayloadCraftingEngine)
        assert scanner.scan_stats['total_requests'] == 0
        assert len(scanner.error_patterns) > 0
        assert len(scanner.scan_configs) == 4
    
    def test_technique_selection(self, scanner, sample_injection_point):
        """Test technique selection for different parameter types."""
        config = scanner.scan_configs[ScanMode.THOROUGH]
        
        # Test string parameter
        techniques = scanner._select_techniques(sample_injection_point, config)
        assert len(techniques) > 0
        assert DetectionTechnique.ERROR_BASED in techniques
        
        # Test numeric parameter
        numeric_point = InjectionPoint(
            name="id",
            value="123",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.NUMERIC,
            url="http://example.com/product",
            method="GET",
            test_priority=9
        )
        techniques = scanner._select_techniques(numeric_point, config)
        assert len(techniques) > 0
    
    def test_technique_mapping(self, scanner):
        """Test detection technique to crafting technique mapping."""
        # Test mappings
        assert scanner._map_to_crafting_technique(DetectionTechnique.ERROR_BASED) == InjectionTechnique.ERROR_BASED
        assert scanner._map_to_crafting_technique(DetectionTechnique.BOOLEAN_BLIND) == InjectionTechnique.BOOLEAN_BASED
        assert scanner._map_to_crafting_technique(DetectionTechnique.TIME_BASED) == InjectionTechnique.TIME_BASED
        assert scanner._map_to_crafting_technique(DetectionTechnique.UNION_BASED) == InjectionTechnique.UNION_BASED
        assert scanner._map_to_crafting_technique(DetectionTechnique.STACKED_QUERIES) == InjectionTechnique.STACKED_QUERIES
    
    def test_parameter_type_mapping(self, scanner):
        """Test parameter type mapping."""
        assert scanner._map_parameter_type(ParameterType.NUMERIC) == 'numeric'
        assert scanner._map_parameter_type(ParameterType.STRING) == 'string'
        assert scanner._map_parameter_type(ParameterType.UNKNOWN) == 'string'
    
    def test_error_based_analysis(self, scanner):
        """Test error-based analysis."""
        error_response = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        result = scanner._analyze_error_based(error_response, "' OR 1=1--", {
            'vulnerable': False, 'confidence': 0.0, 'evidence': []
        })
        
        assert result['vulnerable'] is True
        assert result['confidence'] > 0.5
        assert len(result['evidence']) > 0
        assert any('error' in evidence.lower() for evidence in result['evidence'])
    
    def test_time_based_analysis(self, scanner):
        """Test time-based analysis."""
        # Test significant delay
        result = scanner._analyze_time_based(5.2, "' AND SLEEP(5)--", {
            'vulnerable': False, 'confidence': 0.0, 'evidence': []
        })
        
        assert result['vulnerable'] is True
        assert result['confidence'] > 0.7
        assert len(result['evidence']) > 0
    
    def test_boolean_blind_analysis(self, scanner):
        """Test boolean-based blind analysis."""
        success_response = "Login successful - Welcome to admin panel"
        result = scanner._analyze_boolean_blind(success_response, "admin' AND 1=1--", {
            'vulnerable': False, 'confidence': 0.0, 'evidence': []
        })
        
        assert result['vulnerable'] is True
        assert result['confidence'] > 0.2
        assert len(result['evidence']) > 0
    
    def test_union_based_analysis(self, scanner):
        """Test UNION-based analysis."""
        union_response = "MySQL 5.7.25 - user: root@localhost - database: testdb"
        result = scanner._analyze_union_based(union_response, "' UNION SELECT @@version,user(),database()--", {
            'vulnerable': False, 'confidence': 0.0, 'evidence': []
        })
        
        # This should detect database info patterns
        assert len(result['evidence']) > 0
    
    def test_stacked_queries_analysis(self, scanner):
        """Test stacked queries analysis."""
        stacked_response = "User created successfully. Query executed: 1 rows affected"
        result = scanner._analyze_stacked_queries(stacked_response, "'; INSERT INTO users VALUES('test','pass')--", {
            'vulnerable': False, 'confidence': 0.0, 'evidence': []
        })
        
        assert result['vulnerable'] is True
        assert result['confidence'] > 0.8
        assert len(result['evidence']) > 0
    
    def test_risk_level_calculation(self, scanner, sample_injection_point):
        """Test risk level calculation."""
        # High confidence, high-priority parameter
        high_risk_result = {
            'vulnerable': True,
            'confidence': 0.9,
            'technique': DetectionTechnique.ERROR_BASED,
            'evidence': ['SQL error detected']
        }
        
        risk = scanner._calculate_risk_level(high_risk_result, sample_injection_point)
        assert risk in ['High', 'Critical']
    
    def test_exploitation_potential_assessment(self, scanner):
        """Test exploitation potential assessment."""
        # Error-based with high confidence
        error_result = {
            'vulnerable': True,
            'confidence': 0.9,
            'technique': DetectionTechnique.ERROR_BASED,
            'evidence': ['SQL syntax error detected']
        }
        
        potential = scanner._assess_exploitation_potential(error_result)
        assert potential in ['High', 'Critical']
        
        # Time-based with medium confidence
        time_result = {
            'vulnerable': True,
            'confidence': 0.6,
            'technique': DetectionTechnique.TIME_BASED,
            'evidence': ['Response delay detected']
        }
        
        potential = scanner._assess_exploitation_potential(time_result)
        assert potential in ['Medium', 'High']
    
    @pytest.mark.asyncio
    async def test_send_payload_request_get(self, scanner, sample_injection_point):
        """Test sending GET request with payload."""
        # Mock session response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Test response content")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        scanner.session.get = AsyncMock(return_value=mock_response)
        
        config = scanner.scan_configs[ScanMode.FAST]
        
        result = await scanner._send_payload_request(sample_injection_point, "' OR 1=1--", config)
        
        assert result is not None
        assert result['content'] == "Test response content"
        assert result['status_code'] == 200
        assert 'timing' in result
        assert 'headers' in result
    
    @pytest.mark.asyncio
    async def test_send_payload_request_post(self, scanner):
        """Test sending POST request with payload."""
        post_injection_point = InjectionPoint(
            name="username",
            value="admin",
            injection_type=InjectionPointType.POST_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/login",
            method="POST",
            test_priority=9
        )
        
        # Mock session response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Login response")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        scanner.session.post = AsyncMock(return_value=mock_response)
        
        config = scanner.scan_configs[ScanMode.FAST]
        
        result = await scanner._send_payload_request(post_injection_point, "admin' OR 1=1--", config)
        
        assert result is not None
        assert result['content'] == "Login response"
        assert result['status_code'] == 200
    
    @pytest.mark.asyncio
    async def test_send_payload_request_timeout(self, scanner, sample_injection_point):
        """Test request timeout handling."""
        # Mock timeout exception
        scanner.session.get = AsyncMock(side_effect=asyncio.TimeoutError())
        
        config = scanner.scan_configs[ScanMode.FAST]
        
        result = await scanner._send_payload_request(sample_injection_point, "' AND SLEEP(10)--", config)
        
        assert result is None
    
    def test_database_fingerprinting_patterns(self, scanner):
        """Test database fingerprinting patterns."""
        # Test MySQL patterns
        mysql_patterns = scanner.error_patterns[DatabaseType.MYSQL]
        assert len(mysql_patterns) > 0
        assert any('mysql' in pattern.lower() for pattern in mysql_patterns)
        
        # Test PostgreSQL patterns
        postgresql_patterns = scanner.error_patterns[DatabaseType.POSTGRESQL]
        assert len(postgresql_patterns) > 0
        assert any('postgresql' in pattern.lower() for pattern in postgresql_patterns)
    
    def test_scan_statistics(self, scanner):
        """Test scan statistics tracking."""
        initial_stats = scanner.get_scan_statistics()
        
        assert 'total_requests' in initial_stats
        assert 'vulnerabilities_found' in initial_stats
        assert 'techniques_used' in initial_stats
        assert 'scan_duration' in initial_stats
        
        # Update stats
        scanner.scan_stats['total_requests'] = 50
        scanner.scan_stats['vulnerabilities_found'] = 3
        
        updated_stats = scanner.get_scan_statistics()
        assert updated_stats['total_requests'] == 50
        assert updated_stats['vulnerabilities_found'] == 3

class TestSQLInjectionIntegration:
    """Integration tests for complete SQL injection detection workflow."""
    
    @pytest.fixture
    def vulnerable_injection_points(self):
        """Create sample vulnerable injection points."""
        return [
            InjectionPoint(
                name="q",
                value="test",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.STRING,
                url="http://vulnapp.com/search",
                method="GET",
                test_priority=8
            ),
            InjectionPoint(
                name="username",
                value="admin",
                injection_type=InjectionPointType.POST_PARAMETER,
                parameter_type=ParameterType.STRING,
                url="http://vulnapp.com/login",
                method="POST",
                test_priority=9
            ),
            InjectionPoint(
                name="id",
                value="123",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.NUMERIC,
                url="http://vulnapp.com/product",
                method="GET",
                test_priority=7
            )
        ]
    
    @pytest.mark.asyncio
    async def test_complete_scan_workflow(self, vulnerable_injection_points):
        """Test complete scanning workflow."""
        session = Mock(spec=aiohttp.ClientSession)
        scanner = SQLInjectionScanner(session)
        
        # Mock vulnerable responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="You have an error in your SQL syntax")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        session.get = AsyncMock(return_value=mock_response)
        session.post = AsyncMock(return_value=mock_response)
        
        # Run scan
        findings = await scanner.scan_injection_points(
            vulnerable_injection_points,
            scan_mode=ScanMode.FAST
        )
        
        assert len(findings) > 0
        assert all(isinstance(finding, VulnerabilityFinding) for finding in findings)
    
    @pytest.mark.asyncio
    async def test_scan_with_validation(self, vulnerable_injection_points):
        """Test scanning with vulnerability validation enabled."""
        session = Mock(spec=aiohttp.ClientSession)
        scanner = SQLInjectionScanner(session)
        
        # Mock vulnerable responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="MySQL syntax error at line 1")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        session.get = AsyncMock(return_value=mock_response)
        session.post = AsyncMock(return_value=mock_response)
        
        # Mock AI validator
        scanner.ai_validator.validate_vulnerability = AsyncMock(return_value=True)
        
        # Run scan with validation
        findings = await scanner.scan_injection_points(
            vulnerable_injection_points,
            scan_mode=ScanMode.THOROUGH
        )
        
        assert len(findings) > 0
        # Validation should be called for thorough mode
        assert scanner.ai_validator.validate_vulnerability.called
    
    @pytest.mark.asyncio
    async def test_scan_progress_callback(self, vulnerable_injection_points):
        """Test scan progress callback functionality."""
        session = Mock(spec=aiohttp.ClientSession)
        scanner = SQLInjectionScanner(session)
        
        # Mock responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Normal response")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        session.get = AsyncMock(return_value=mock_response)
        session.post = AsyncMock(return_value=mock_response)
        
        # Progress tracking
        progress_updates = []
        
        def progress_callback(current, total, point):
            progress_updates.append((current, total, point.name))
        
        # Run scan with progress callback
        findings = await scanner.scan_injection_points(
            vulnerable_injection_points,
            scan_mode=ScanMode.FAST,
            progress_callback=progress_callback
        )
        
        assert len(progress_updates) > 0
        assert progress_updates[-1][0] <= progress_updates[-1][1]  # current <= total
    
    @pytest.mark.asyncio
    async def test_vulnerability_finding_creation(self, vulnerable_injection_points):
        """Test vulnerability finding creation and metadata."""
        session = Mock(spec=aiohttp.ClientSession)
        scanner = SQLInjectionScanner(session)
        
        # Mock vulnerable response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="ORA-00933: SQL command not properly ended")
        mock_response.headers = {'Content-Type': 'text/html'}
        
        session.get = AsyncMock(return_value=mock_response)
        session.post = AsyncMock(return_value=mock_response)
        
        # Run scan
        findings = await scanner.scan_injection_points(
            [vulnerable_injection_points[0]],  # Test with one point
            scan_mode=ScanMode.FAST
        )
        
        if findings:  # If vulnerability found
            finding = findings[0]
            assert isinstance(finding, VulnerabilityFinding)
            assert finding.injection_point == vulnerable_injection_points[0]
            assert finding.technique in DetectionTechnique
            assert 0.0 <= finding.confidence <= 1.0
            assert isinstance(finding.evidence, list)
            assert finding.risk_level in ['Low', 'Medium', 'High', 'Critical']

class TestPerformance:
    """Performance tests for SQL injection detection system."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner for performance testing."""
        session = Mock(spec=aiohttp.ClientSession)
        return SQLInjectionScanner(session)
    
    def test_payload_generation_performance(self, scanner):
        """Test payload generation performance."""
        context = PayloadCraftingContext(
            injection_point=InjectionPoint(
                name="id",
                value="123",
                injection_type=InjectionPointType.QUERY_PARAMETER,
                parameter_type=ParameterType.NUMERIC,
                url="http://example.com/test",
                method="GET"
            )
        )
        
        # Measure payload generation time
        start_time = time.time()
        
        payloads = scanner.payload_engine.craft_payloads(
            context.injection_point,
            max_payloads=100
        )
        
        end_time = time.time()
        generation_time = end_time - start_time
        
        assert len(payloads) > 0
        assert generation_time < 1.0  # Should generate 100 payloads in under 1 second
    
    def test_technique_selection_performance(self, scanner):
        """Test technique selection performance."""
        injection_point = InjectionPoint(
            name="q",
            value="test",
            injection_type=InjectionPointType.QUERY_PARAMETER,
            parameter_type=ParameterType.STRING,
            url="http://example.com/test",
            method="GET",
            test_priority=8
        )
        
        config = scanner.scan_configs[ScanMode.AGGRESSIVE]
        
        # Measure technique selection time
        start_time = time.time()
        
        for _ in range(1000):  # Test 1000 selections
            techniques = scanner._select_techniques(injection_point, config)
        
        end_time = time.time()
        selection_time = end_time - start_time
        
        assert selection_time < 0.1  # Should complete 1000 selections in under 0.1 seconds

if __name__ == "__main__":
    pytest.main([__file__]) 