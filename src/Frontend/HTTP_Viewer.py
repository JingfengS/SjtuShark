import tempfile
import webbrowser
import os
import json
import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk, scrolledtext
import tkinter.font as tkFont

class HTTPContentViewer:
    """
    HTTP内容查看器，提供美化显示、HTML预览和浏览器打开功能
    """
    
    def __init__(self):
        self.temp_files = []  # 追踪临时文件以便清理
        
    def parse_http_message(self, data):
        """
        解析HTTP消息，分离请求/响应的各个部分
        返回结构化的HTTP数据
        """
        if not data:
            return None
            
        try:
            # 尝试解码数据
            if isinstance(data, bytes):
                # 先尝试UTF-8
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError:
                    # 失败则尝试Latin-1
                    text = data.decode('latin-1', errors='ignore')
            else:
                text = data
            
            # 分离请求和响应
            messages = []
            
            # 查找所有HTTP消息的起始位置
            request_pattern = r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/\d\.\d'
            response_pattern = r'^HTTP/\d\.\d\s+\d{3}'
            
            # 分割成多个HTTP消息
            parts = re.split(r'(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/\d\.\d|HTTP/\d\.\d\s+\d{3})', text, flags=re.MULTILINE)
            
            for part in parts:
                if not part.strip():
                    continue
                    
                msg = self._parse_single_http_message(part)
                if msg:
                    messages.append(msg)
            
            return messages
            
        except Exception as e:
            return [{"error": f"解析错误: {str(e)}", "raw": data}]
    
    def _parse_single_http_message(self, text):
        """解析单个HTTP消息"""
        lines = text.split('\n')
        if not lines:
            return None
            
        first_line = lines[0].strip()
        
        # 判断是请求还是响应
        if first_line.startswith('HTTP/'):
            return self._parse_http_response(text)
        elif any(first_line.startswith(method) for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']):
            return self._parse_http_request(text)
        else:
            return None
    
    def _parse_http_request(self, text):
        """解析HTTP请求"""
        try:
            # 分离头部和正文
            parts = text.split('\r\n\r\n', 1)
            if len(parts) == 1:
                parts = text.split('\n\n', 1)
            
            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ''
            
            # 解析请求行
            lines = headers_text.split('\n')
            request_line = lines[0].strip()
            parts = request_line.split(' ', 2)
            
            if len(parts) < 3:
                return None
                
            method = parts[0]
            path = parts[1]
            version = parts[2]
            
            # 解析URL和查询参数
            parsed_url = urlparse(path)
            query_params = parse_qs(parsed_url.query)
            
            # 解析头部
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # 解析正文（如果是JSON）
            parsed_body = body
            if body and headers.get('Content-Type', '').startswith('application/json'):
                try:
                    parsed_body = json.loads(body)
                except:
                    pass
            
            return {
                'type': 'request',
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'query_params': query_params,
                'body': body,
                'parsed_body': parsed_body,
                'host': headers.get('Host', 'unknown')
            }
            
        except Exception as e:
            return None
    
    def _parse_http_response(self, text):
        """解析HTTP响应"""
        try:
            # 分离头部和正文
            parts = text.split('\r\n\r\n', 1)
            if len(parts) == 1:
                parts = text.split('\n\n', 1)
            
            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ''
            
            # 解析状态行
            lines = headers_text.split('\n')
            status_line = lines[0].strip()
            parts = status_line.split(' ', 2)
            
            if len(parts) < 2:
                return None
                
            version = parts[0]
            status_code = parts[1]
            status_text = parts[2] if len(parts) > 2 else ''
            
            # 解析头部
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # 处理压缩的内容
            if headers.get('Content-Encoding') == 'gzip' and body:
                try:
                    import gzip
                    body = gzip.decompress(body.encode('latin-1')).decode('utf-8', errors='ignore')
                except:
                    pass
            
            # 判断内容类型
            content_type = headers.get('Content-Type', '')
            is_html = 'text/html' in content_type
            is_json = 'application/json' in content_type
            is_javascript = 'application/javascript' in content_type or 'text/javascript' in content_type
            is_css = 'text/css' in content_type
            
            # 解析正文
            parsed_body = body
            if is_json and body:
                try:
                    parsed_body = json.loads(body)
                except:
                    pass
            elif is_html and body:
                try:
                    soup = BeautifulSoup(body, 'html.parser')
                    parsed_body = soup.prettify()
                except:
                    pass
            
            return {
                'type': 'response',
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body,
                'parsed_body': parsed_body,
                'content_type': content_type,
                'is_html': is_html,
                'is_json': is_json,
                'is_javascript': is_javascript,
                'is_css': is_css
            }
            
        except Exception as e:
            return None
    
    def create_html_preview(self, http_messages):
        """
        创建HTTP会话的HTML预览
        """
        html_parts = []
        
        html_parts.append("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>HTTP Session Preview</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                .message {
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .request {
                    border-left: 4px solid #4CAF50;
                }
                .response {
                    border-left: 4px solid #2196F3;
                }
                .status-line {
                    font-size: 18px;
                    font-weight: bold;
                    margin-bottom: 10px;
                    color: #333;
                }
                .headers {
                    background: #f9f9f9;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                }
                .header {
                    margin: 5px 0;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 14px;
                }
                .header-key {
                    color: #0066cc;
                    font-weight: bold;
                }
                .body {
                    background: #f0f0f0;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 10px;
                    overflow-x: auto;
                }
                .json {
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 14px;
                    white-space: pre-wrap;
                }
                .html-content {
                    border: 1px solid #ccc;
                    padding: 10px;
                    background: white;
                    border-radius: 4px;
                }
                .method {
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    color: white;
                    font-weight: bold;
                    margin-right: 10px;
                }
                .method-get { background: #4CAF50; }
                .method-post { background: #FF9800; }
                .method-put { background: #2196F3; }
                .method-delete { background: #f44336; }
                .status-2xx { color: #4CAF50; }
                .status-3xx { color: #FF9800; }
                .status-4xx { color: #f44336; }
                .status-5xx { color: #d32f2f; }
                .query-params {
                    background: #e8f5e9;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                }
            </style>
        </head>
        <body>
            <h1>HTTP Session Analysis</h1>
        """)
        
        for msg in http_messages:
            if msg.get('error'):
                html_parts.append(f'<div class="message error">{msg["error"]}</div>')
                continue
                
            if msg['type'] == 'request':
                method_class = f"method-{msg['method'].lower()}"
                html_parts.append(f'''
                <div class="message request">
                    <div class="status-line">
                        <span class="method {method_class}">{msg['method']}</span>
                        {msg['path']} {msg['version']}
                    </div>
                    <div class="host">Host: {msg['host']}</div>
                ''')
                
                # 查询参数
                if msg['query_params']:
                    html_parts.append('<div class="query-params"><strong>Query Parameters:</strong><br>')
                    for key, values in msg['query_params'].items():
                        html_parts.append(f'<div class="header"><span class="header-key">{key}:</span> {", ".join(values)}</div>')
                    html_parts.append('</div>')
                
            else:  # response
                status_class = f"status-{msg['status_code'][0]}xx"
                html_parts.append(f'''
                <div class="message response">
                    <div class="status-line {status_class}">
                        {msg['version']} {msg['status_code']} {msg['status_text']}
                    </div>
                ''')
            
            # 头部
            html_parts.append('<div class="headers"><strong>Headers:</strong>')
            for key, value in msg['headers'].items():
                html_parts.append(f'<div class="header"><span class="header-key">{key}:</span> {value}</div>')
            html_parts.append('</div>')
            
            # 正文
            if msg.get('body'):
                html_parts.append('<div class="body"><strong>Body:</strong><br>')
                
                if msg.get('is_json') and isinstance(msg.get('parsed_body'), (dict, list)):
                    json_str = json.dumps(msg['parsed_body'], indent=2, ensure_ascii=False)
                    html_parts.append(f'<pre class="json">{self._escape_html(json_str)}</pre>')
                elif msg.get('is_html'):
                    # 对于HTML响应，显示预览
                    html_parts.append('<div class="html-content">')
                    html_parts.append('<em>HTML Content Preview:</em><br>')
                    # 这里直接嵌入HTML内容（在实际使用中可能需要更多的安全处理）
                    html_parts.append(msg['body'])
                    html_parts.append('</div>')
                else:
                    # 其他类型的内容
                    body_preview = msg['body'][:1000] if len(msg['body']) > 1000 else msg['body']
                    html_parts.append(f'<pre>{self._escape_html(body_preview)}</pre>')
                    if len(msg['body']) > 1000:
                        html_parts.append(f'<em>... (truncated, total {len(msg["body"])} bytes)</em>')
                
                html_parts.append('</div>')
            
            html_parts.append('</div>')
        
        html_parts.append('</body></html>')
        return ''.join(html_parts)
    
    def _escape_html(self, text):
        """转义HTML特殊字符"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    def save_and_open_in_browser(self, http_messages):
        """
        保存HTTP会话为HTML并在浏览器中打开
        """
        try:
            # 创建HTML内容
            html_content = self.create_html_preview(http_messages)
            
            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(html_content)
                temp_path = f.name
            
            self.temp_files.append(temp_path)
            
            # 在默认浏览器中打开
            webbrowser.open(f'file://{os.path.abspath(temp_path)}')
            
            return True, temp_path
        except Exception as e:
            return False, str(e)
    
    def save_raw_html_response(self, http_messages):
        """
        提取并保存原始HTML响应内容
        """
        for msg in http_messages:
            if msg.get('type') == 'response' and msg.get('is_html') and msg.get('body'):
                try:
                    # 创建临时HTML文件
                    with tempfile.NamedTemporaryFile(mode='w', suffix='_raw.html', delete=False, encoding='utf-8') as f:
                        f.write(msg['body'])
                        temp_path = f.name
                    
                    self.temp_files.append(temp_path)
                    
                    # 在浏览器中打开原始HTML
                    webbrowser.open(f'file://{os.path.abspath(temp_path)}')
                    
                    return True, temp_path
                except Exception as e:
                    return False, str(e)
        
        return False, "No HTML response found"
    
    def cleanup_temp_files(self):
        """清理临时文件"""
        for file_path in self.temp_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
        self.temp_files.clear()
    
    def create_formatted_text_view(self, http_messages):
        """
        创建格式化的文本视图（用于在GUI中显示）
        """
        formatted_text = []
        
        for i, msg in enumerate(http_messages):
            if i > 0:
                formatted_text.append("\n" + "="*70 + "\n")
            
            if msg.get('error'):
                formatted_text.append(f"ERROR: {msg['error']}\n")
                continue
            
            if msg['type'] == 'request':
                formatted_text.append(f"REQUEST #{i+1}\n")
                formatted_text.append(f"{msg['method']} {msg['path']} {msg['version']}\n")
                formatted_text.append(f"Host: {msg['host']}\n")
                
                if msg['query_params']:
                    formatted_text.append("\nQuery Parameters:\n")
                    for key, values in msg['query_params'].items():
                        formatted_text.append(f"  {key}: {', '.join(values)}\n")
            
            else:  # response
                formatted_text.append(f"RESPONSE #{i+1}\n")
                formatted_text.append(f"{msg['version']} {msg['status_code']} {msg['status_text']}\n")
                formatted_text.append(f"Content-Type: {msg['content_type']}\n")
            
            # Headers
            formatted_text.append("\nHeaders:\n")
            for key, value in msg['headers'].items():
                formatted_text.append(f"  {key}: {value}\n")
            
            # Body
            if msg.get('body'):
                formatted_text.append("\nBody:\n")
                if msg.get('is_json') and isinstance(msg.get('parsed_body'), (dict, list)):
                    formatted_text.append(json.dumps(msg['parsed_body'], indent=2, ensure_ascii=False))
                elif msg.get('is_html'):
                    # 对于HTML，显示美化后的版本
                    formatted_text.append("[HTML Content - Beautified]\n")
                    formatted_text.append(msg.get('parsed_body', msg['body'])[:2000])
                    if len(msg.get('parsed_body', msg['body'])) > 2000:
                        formatted_text.append("\n... (truncated)")
                else:
                    body_preview = msg['body'][:1000]
                    formatted_text.append(body_preview)
                    if len(msg['body']) > 1000:
                        formatted_text.append(f"\n... (truncated, total {len(msg['body'])} bytes)")
            
            formatted_text.append("\n")
        
        return ''.join(formatted_text)