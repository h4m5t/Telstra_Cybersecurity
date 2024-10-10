# firewall_server.py
# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

host = "localhost"
port = 8000

#########
# Handle the response here 
def block_request(self):
    print("Blocking malicious request from:", self.client_address)
    self.send_response(403)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    response = '{"message": "403 Forbidden: Malicious request blocked."}'
    self.wfile.write(response.encode('utf-8'))

def allow_request(self):
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    response = '{"message": "200 OK"}'
    self.wfile.write(response.encode('utf-8'))

#########

# Define malicious parameters associated with Spring4Shell vulnerability
MALICIOUS_PARAMS = [
    'class.module.classLoader.resources.context.parent.pipeline.first.pattern',
    'class.module.classLoader.resources.context.parent.pipeline.first.suffix',
    'class.module.classLoader.resources.context.parent.pipeline.first.directory',
    'class.module.classLoader.resources.context.parent.pipeline.first.prefix',
    'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat'
]

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        allow_request(self)

    def do_POST(self):
        # Check if the request path is the targeted endpoint
        if self.path == '/tomcatwar.jsp':
            # Retrieve and decode the request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            
            # Check for the presence of any malicious parameters
            if any(param in params for param in MALICIOUS_PARAMS):
                block_request(self)
                return
            else:
                allow_request(self)
                return
        else:
            # For all other POST requests, allow them
            allow_request(self)

    def log_message(self, format, *args):
        # Override to suppress default logging
        return

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)