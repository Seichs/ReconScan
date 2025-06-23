"""
ReconScan False Positive Filters

Intelligent filtering system for common false positives in vulnerability scanning.
Reduces noise by identifying known safe endpoints and parameter combinations.
"""

from urllib.parse import urlparse

class FalsePositiveFilters:
    """
    Advanced false positive detection system for vulnerability scanners.
    
    Provides comprehensive filtering for WordPress, CMS endpoints, and common
    web application patterns that trigger security alerts but are actually safe.
    """
    
    def __init__(self):
        """Initialize false positive detection system."""
        pass
    
    def is_sql_injection_false_positive(self, test_url, param_name, payload=None):
        """
        Check if a URL/parameter combination is a known false positive for SQL injection.
        Enhanced with comprehensive WordPress and CMS false positive detection.
        
        Args:
            test_url (str): The URL being tested
            param_name (str): Parameter name being tested
            payload (str, optional): The payload being tested
            
        Returns:
            dict: False positive information with reason and AI label, or None if not a false positive
        """
        parsed_url = urlparse(test_url)
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # 1. WordPress oEmbed REST API endpoints
        if '/wp-json/oembed/' in path and param_name == 'url':
            return {
                'is_false_positive': True,
                'reason': 'WordPress oEmbed API - URL parameter used for external embed requests, not SQL queries',
                'ai_label': 'false_positive.sql_pattern_in_url_param',
                'confidence': 'high'
            }
        
        # 2. WordPress AJAX endpoints (admin-ajax.php)
        if '/wp-admin/admin-ajax.php' in path:
            if param_name in ['action', 'data', 'nonce', '_ajax_nonce', '_wpnonce']:
                return {
                    'is_false_positive': True,
                    'reason': 'WordPress AJAX endpoint - legitimate plugin/theme communication',
                    'ai_label': 'false_positive.legit_ajax_call',
                    'confidence': 'high'
                }
        
        # 3. WordPress XML-RPC endpoint
        if '/xmlrpc.php' in path:
            return {
                'is_false_positive': True,
                'reason': 'WordPress XML-RPC endpoint - used for pingbacks, Jetpack, and remote publishing',
                'ai_label': 'false_positive.legit_xmlrpc_usage',
                'confidence': 'medium'
            }
        
        # 4. WordPress login endpoint (single attempts)
        if '/wp-login.php' in path and param_name in ['log', 'pwd', 'redirect_to']:
            return {
                'is_false_positive': True,
                'reason': 'WordPress login endpoint - legitimate authentication attempt',
                'ai_label': 'false_positive.failed_login_single_attempt',
                'confidence': 'medium'
            }
        
        # 5. WordPress REST API endpoints that handle URL parameters safely
        wordpress_safe_paths = [
            '/wp-json/wp/v2/media',
            '/wp-json/wp/v2/embed',
            '/wp-json/oembed/1.0/embed',
            '/wp-content/plugins/',
            '/wp-includes/',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/users'
        ]
        
        if any(safe_path in path for safe_path in wordpress_safe_paths):
            if param_name in ['url', 'src', 'href', 'link', 'callback', 'format', 'context', 'embed']:
                return {
                    'is_false_positive': True,
                    'reason': 'WordPress REST API endpoint - parameters handled safely by WordPress core',
                    'ai_label': 'false_positive.wordpress_rest_api_safe_param',
                    'confidence': 'high'
                }
        
        # 6. Contact forms and message parameters
        if param_name in ['message', 'comment', 'content', 'text', 'body'] and payload:
            # Check if it's just user input with SQL terms (not actual injection)
            harmless_sql_patterns = [
                'drop table', 'select * from', 'union select', 'delete from'
            ]
            if any(pattern in payload.lower() for pattern in harmless_sql_patterns):
                if 'contact' in path or 'form' in path or 'comment' in path:
                    return {
                        'is_false_positive': True,
                        'reason': 'Contact form with SQL keywords in message - likely user testing or typing literally',
                        'ai_label': 'false_positive.user_input_with_sql_terms',
                        'confidence': 'medium'
                    }
        
        # 7. Social media embed endpoints
        social_embed_patterns = [
            '/embed/', '/oembed/', '/api/oembed', '/services/oembed'
        ]
        
        if any(pattern in path for pattern in social_embed_patterns):
            if param_name in ['url', 'src', 'link', 'href']:
                return {
                    'is_false_positive': True,
                    'reason': 'Social media embed endpoint - URL parameters for external content embedding',
                    'ai_label': 'false_positive.social_embed_url_param',
                    'confidence': 'high'
                }
        
        # 8. Known safe API endpoints that handle URLs
        safe_api_patterns = [
            '/api/v1/oembed',
            '/api/v2/oembed', 
            '/_oembed',
            '/oembed.json',
            '/oembed.xml',
            '/api/embed',
            '/preview'
        ]
        
        if any(pattern in path for pattern in safe_api_patterns):
            if param_name in ['url', 'src', 'link', 'href', 'callback']:
                return {
                    'is_false_positive': True,
                    'reason': 'oEmbed/preview API endpoint - URL parameters for content fetching',
                    'ai_label': 'false_positive.oembed_api_url_param',
                    'confidence': 'high'
                }
        
        # 9. Content Management System safe endpoints
        cms_safe_patterns = [
            '/drupal/oembed',
            '/joomla/oembed',
            '/typo3/oembed',
            '/system/ajax',
            '/admin/ajax'
        ]
        
        if any(pattern in path for pattern in cms_safe_patterns):
            if param_name in ['url', 'src', 'action', 'callback', 'data']:
                return {
                    'is_false_positive': True,
                    'reason': 'CMS system endpoint - handled by framework with built-in protection',
                    'ai_label': 'false_positive.cms_system_endpoint',
                    'confidence': 'medium'
                }
        
        # 10. URL-encoded HTML/JS tags in parameters (often for previews/embeds)
        if payload and param_name in ['preview', 'content', 'html', 'embed_code']:
            encoded_patterns = ['%3Cscript%3E', '%3Ciframe%3E', '%3Cimg%20', '<script>', '<iframe>', '<img ']
            if any(pattern in payload.lower() for pattern in encoded_patterns):
                return {
                    'is_false_positive': True,
                    'reason': 'HTML/JS tags in preview/embed parameter - likely for content preview, not execution',
                    'ai_label': 'false_positive.encoded_html_tags_for_embed',
                    'confidence': 'medium'
                }
        
        # 11. Search parameters with SQL keywords (often user search terms)
        if param_name in ['q', 'query', 'search', 's'] and payload:
            if any(keyword in payload.lower() for keyword in ['select', 'union', 'drop', 'insert']):
                return {
                    'is_false_positive': True,
                    'reason': 'Search parameter with SQL keywords - likely user search terms, not injection',
                    'ai_label': 'false_positive.search_with_sql_keywords',
                    'confidence': 'low'
                }
        
        return None

    def is_xss_false_positive(self, test_url, param_name, payload=None):
        """
        Check if a URL/parameter combination is a known false positive for XSS.
        
        Args:
            test_url (str): The URL being tested
            param_name (str): Parameter name being tested
            payload (str, optional): The payload being tested
            
        Returns:
            dict: False positive information or None if not a false positive
        """
        parsed_url = urlparse(test_url)
        path = parsed_url.path.lower()
        
        # HTML/JS in preview or embed parameters (often for content management)
        if param_name in ['preview', 'content', 'html', 'embed_code', 'widget_content']:
            return {
                'is_false_positive': True,
                'reason': 'HTML/JS content in preview/embed parameter - likely for content management, not execution',
                'ai_label': 'false_positive.script_tag_in_url_but_not_executed',
                'confidence': 'medium'
            }
        
        # WordPress admin areas where HTML is expected
        if '/wp-admin/' in path and param_name in ['content', 'excerpt', 'meta_value']:
            return {
                'is_false_positive': True,
                'reason': 'WordPress admin area - HTML content expected in content management',
                'ai_label': 'false_positive.html_in_admin_content',
                'confidence': 'high'
            }
        
        # oEmbed and embed services that may contain HTML
        embed_patterns = ['/oembed', '/embed/', '/api/embed']
        if any(pattern in path for pattern in embed_patterns):
            if param_name in ['url', 'html', 'content', 'code']:
                return {
                    'is_false_positive': True,
                    'reason': 'Embed service endpoint - HTML/JS expected for embed code generation',
                    'ai_label': 'false_positive.embedded_html_for_service',
                    'confidence': 'high'
                }
        
        return None 