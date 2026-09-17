import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from collections import defaultdict
import re

class ApplicationMapper:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()
        self.endpoints = defaultdict(list)
        self.forms = []
        self.api_endpoints = []
        self.session = requests.Session()
        
    def categorize_endpoint(self, url, method='GET'):
        """Categorize endpoints by function"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        categories = {
            'auth': ['login', 'signin', 'authenticate', 'register', 'signup'],
            'admin': ['admin', 'dashboard', 'manage', 'control'],
            'api': ['api', 'rest', 'graphql', 'json'],
            'file': ['upload', 'download', 'file', 'attachment'],
            'user': ['profile', 'account', 'user', 'settings'],
            'search': ['search', 'find', 'query'],
            'checkout': ['cart', 'checkout', 'payment', 'order']
        }
        
        for category, keywords in categories.items():
            if any(kw in path for kw in keywords):
                self.endpoints[category].append({
                    'url': url,
                    'method': method,
                    'params': self.extract_params(url)
                })
                return category
        
        self.endpoints['other'].append({
            'url': url,
            'method': method,
            'params': self.extract_params(url)
        })
        return 'other'
    
    def extract_params(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        if parsed.query:
            return [p.split('=')[0] for p in parsed.query.split('&')]
        return []
    
    def analyze_form(self, form, page_url):
        """Deep form analysis"""
        form_data = {
            'action': urljoin(page_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'csrf_token': None,
            'hidden_fields': []
        }
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_info = {
                'name': input_tag.get('name'),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            
            form_data['inputs'].append(input_info)
            
            # Detect CSRF tokens
            if input_tag.get('type') == 'hidden':
                name = input_tag.get('name', '').lower()
                if any(token in name for token in ['csrf', 'token', '_token']):
                    form_data['csrf_token'] = input_info
                else:
                    form_data['hidden_fields'].append(input_info)
        
        self.forms.append(form_data)
        return form_data
    
    def find_api_endpoints(self, content):
        """Extract API endpoints from JavaScript"""
        # Common API patterns
        patterns = [
            r'["\']/(api|rest|v\d+)/[a-zA-Z0-9/_-]+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                full_url = urljoin(self.base_url, match)
                if full_url not in [e['url'] for e in self.api_endpoints]:
                    self.api_endpoints.append({
                        'url': full_url,
                        'found_in': 'javascript_analysis'
                    })
    
    def crawl(self, url, depth=2):
        """Crawl and map application"""
        if depth == 0 or url in self.visited:
            return
        
        self.visited.add(url)
        print(f"[*] Crawling: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Categorize this endpoint
            category = self.categorize_endpoint(url)
            print(f"    Category: {category}")
            
            # Analyze forms
            for form in soup.find_all('form'):
                form_data = self.analyze_form(form, url)
                print(f"    Found form: {form_data['method']} -> {form_data['action']}")
            
            # Find API endpoints in JavaScript
            for script in soup.find_all('script'):
                if script.string:
                    self.find_api_endpoints(script.string)
            
            # Follow links
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if next_url.startswith(self.base_url):
                    self.crawl(next_url, depth - 1)
                    
        except Exception as e:
            print(f"    Error: {e}")
    
    def generate_report(self):
        """Generate mapping report"""
        print("\n" + "="*60)
        print("APPLICATION MAPPING REPORT")
        print("="*60)
        
        print("\n[+] Endpoints by Category:")
        for category, endpoints in self.endpoints.items():
            print(f"\n  {category.upper()} ({len(endpoints)} endpoints):")
            for ep in endpoints[:5]:  # Show first 5
                print(f"    - {ep['method']} {ep['url']}")
                if ep['params']:
                    print(f"      Params: {', '.join(ep['params'])}")
        
        print(f"\n[+] Forms Found: {len(self.forms)}")
        for form in self.forms[:5]:
            print(f"  - {form['method']} {form['action']}")
            print(f"    Inputs: {len(form['inputs'])}")
            if form['csrf_token']:
                print(f"    CSRF Protection: YES")
            else:
                print(f"    CSRF Protection: NO - POTENTIAL VULNERABILITY")
        
        print(f"\n[+] API Endpoints Discovered: {len(self.api_endpoints)}")
        for api in self.api_endpoints[:5]:
            print(f"  - {api['url']}")
        
        print(f"\n[+] Total Pages Visited: {len(self.visited)}")
        
        # Testing priorities
        print("\n[!] HIGH PRIORITY TESTING TARGETS:")
        if self.endpoints['auth']:
            print("  - Authentication endpoints (bruteforce, SQLi, auth bypass)")
        if self.endpoints['file']:
            print("  - File operation endpoints (upload RCE, LFI, path traversal)")
        if self.endpoints['api']:
            print("  - API endpoints (authorization, IDOR, mass assignment)")
        if any(not form['csrf_token'] for form in self.forms):
            print("  - Forms without CSRF tokens (CSRF attacks)")

# Example usage
if __name__ == "__main__":
    # Example: mapper = ApplicationMapper("http://target.com")
    # mapper.crawl(mapper.base_url, depth=3)
    # mapper.generate_report()
    
    print("Smart Application Mapper")
    print("Usage:")
    print("  mapper = ApplicationMapper('http://target.com')")
    print("  mapper.crawl(mapper.base_url, depth=3)")
    print("  mapper.generate_report()")