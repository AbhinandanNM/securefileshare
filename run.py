import os
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from app import create_app

app = create_app()

class HTTPRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', f'https://localhost:5000{self.path}')
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass  # Suppress console noise

def start_http_redirect_server(port=5080):
    try:
        httpd = HTTPServer(('0.0.0.0', port), HTTPRedirectHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        print(f" * HTTP redirector active on http://127.0.0.1:{port} (redirects to https://localhost:5000/)")
    except Exception as e:
        pass

def open_browser(url, delay=1.2):
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()

if __name__ == '__main__':
    use_http_only = '--http' in sys.argv or '--no-ssl' in sys.argv or os.environ.get('DISABLE_SSL') == '1'

    start_http_redirect_server(5080)

    if use_http_only:
        print("\n============================================================")
        print(" [CNS] Running in plain HTTP mode (SSL disabled)")
        print(" Access URL: http://localhost:5000")
        print("============================================================\n")
        open_browser('http://localhost:5000')
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        print("\n============================================================")
        print(" [CNS] Running in Secure HTTPS mode (AES-256 + TLS / O4)")
        print(" Access URL: https://localhost:5000")
        print(" Note: Chrome will show an SSL warning for self-signed dev cert.")
        print("       Click 'Advanced' -> 'Proceed to localhost (unsafe)'.")
        print("============================================================\n")
        open_browser('https://localhost:5000')
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            ssl_context='adhoc'
        )
