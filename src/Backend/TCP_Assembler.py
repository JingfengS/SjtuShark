import threading
from collections import defaultdict
from scapy.layers.inet import IP, TCP
import datetime

class ImprovedTCPReassembler:
    """
    改进的TCP报文重组器，支持双向流、乱序包、重传等复杂情况
    """
    
    def __init__(self):
        self.tcp_streams = {}  # 存储TCP流
        self.lock = threading.RLock()  # 线程安全
        
    def get_stream_key(self, packet):
        """
        生成TCP流的唯一标识符
        使用四元组：(src_ip, src_port, dst_ip, dst_port)
        """
        if IP in packet and TCP in packet:
            return (
                packet[IP].src,
                packet[TCP].sport,
                packet[IP].dst,
                packet[TCP].dport
            )
        return None
    
    def get_bidirectional_key(self, key):
        """
        获取双向流的统一标识符
        确保 A->B 和 B->A 使用相同的会话标识
        """
        if key is None:
            return None
        # 将较小的IP:Port组合放在前面，确保双向流使用同一个key
        forward = (key[0], key[1])
        reverse = (key[2], key[3])
        if forward < reverse:
            return key
        else:
            return (key[2], key[3], key[0], key[1])
    
    def process_packet(self, packet):
        """
        处理单个TCP包，返回该包所属流的信息
        """
        if not (IP in packet and TCP in packet):
            return None
            
        with self.lock:
            # 获取流标识符
            stream_key = self.get_stream_key(packet)
            if not stream_key:
                return None
                
            # 获取双向流标识符
            session_key = self.get_bidirectional_key(stream_key)
            
            # 如果是新的TCP流，初始化
            if session_key not in self.tcp_streams:
                self.tcp_streams[session_key] = {
                    'client': stream_key[:2],  # (client_ip, client_port)
                    'server': stream_key[2:],  # (server_ip, server_port)
                    'client_to_server': TCPDirection(),
                    'server_to_client': TCPDirection(),
                    'start_time': datetime.datetime.now(),
                    'syn_seen': False,
                    'fin_seen': False,
                    'protocol': 'TCP', # 默认协议，后续可能识别为HTTP/HTTPS
                    'http_msgs': []     # ⽤来保存解析好的 HTTP 请求/响应
                }
            
            stream = self.tcp_streams[session_key]
            
            # 判断数据方向
            if (packet[IP].src, packet[TCP].sport) == stream['client']:
                direction = stream['client_to_server']
                direction_name = 'client_to_server'
            else:
                direction = stream['server_to_client']
                direction_name = 'server_to_client'
            
            # 处理TCP标志位
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x02:  # SYN
                stream['syn_seen'] = True
                direction.isn = packet[TCP].seq
                direction.next_seq = packet[TCP].seq + 1
                
            if tcp_flags & 0x01:  # FIN
                stream['fin_seen'] = True
            
            # 提取并重组数据
            payload = bytes(packet[TCP].payload)
            if payload:
                self._reassemble_data(direction, packet[TCP].seq, payload)
            
            # 尝试识别应用层协议
            self._identify_protocol(stream, packet)
            
            return {
                'session_key': session_key,
                'direction': direction_name,
                'stream': stream
            }
    
    def _reassemble_data(self, direction, seq, data):
        """
        重组TCP数据
        处理乱序、重传、重叠等情况
        """
        if not data:
            return
            
        # 如果是第一个数据包，初始化期望序列号
        if direction.next_seq is None:
            direction.next_seq = seq
            direction.isn = seq
        
        # 计算相对序列号（相对于初始序列号）
        relative_seq = seq - direction.isn
        
        # 检查是否是重传包（序列号小于已接收的）
        if relative_seq + len(data) <= len(direction.data):
            direction.retransmissions += 1
            return
        
        # 如果是期望的序列号，直接添加数据
        if seq == direction.next_seq:
            # 检查是否与已有数据重叠
            overlap = len(direction.data) - relative_seq
            if overlap > 0:
                # 跳过重叠部分
                data = data[overlap:]
            
            direction.data += data
            direction.next_seq = seq + len(data)
            
            # 处理缓冲区中的乱序包
            self._process_out_of_order_buffer(direction)
        
        # 如果是乱序包，加入缓冲区
        elif seq > direction.next_seq:
            direction.out_of_order_packets[seq] = data
            direction.out_of_order_count += 1
            
            # 如果缓冲区过大，可能需要清理
            if len(direction.out_of_order_packets) > 1000:
                self._cleanup_old_packets(direction)
    
    def _process_out_of_order_buffer(self, direction):
        """
        处理乱序缓冲区中的数据包
        """
        while direction.next_seq in direction.out_of_order_packets:
            data = direction.out_of_order_packets.pop(direction.next_seq)
            direction.data += data
            direction.next_seq += len(data)
    
    def _cleanup_old_packets(self, direction):
        """
        清理过旧的乱序包（可能永远不会被使用）
        """
        threshold = direction.next_seq - 65536  # 64KB窗口
        old_packets = [seq for seq in direction.out_of_order_packets if seq < threshold]
        for seq in old_packets:
            del direction.out_of_order_packets[seq]
    
    def _identify_protocol(self, stream, packet):
        """
        识别应用层协议
        """
        # 检查端口号
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        # HTTPS
        if sport == 443 or dport == 443:
            # 检查TLS握手特征
            data = stream['client_to_server'].data + stream['server_to_client'].data
            if data.startswith(b'\x16\x03'):  # TLS Handshake
                stream['protocol'] = 'HTTPS'
                return
        
        # HTTP
        if sport == 80 or dport == 80:
            # 检查HTTP特征
            client_data = stream['client_to_server'].data
            server_data = stream['server_to_client'].data
            
            # 检查HTTP请求方法
            if any(client_data.startswith(method) for method in 
                   [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ']):
                stream['protocol'] = 'HTTP'
                return
            
            # 检查HTTP响应
            if server_data.startswith(b'HTTP/'):
                stream['protocol'] = 'HTTP'
                return
    
    def get_stream_data(self, session_key, direction='both'):
        """
        获取指定流的重组数据
        
        :param session_key: 会话标识符
        :param direction: 'client_to_server', 'server_to_client', 或 'both'
        :return: 重组后的数据
        """
        with self.lock:
            if session_key not in self.tcp_streams:
                return None
                
            stream = self.tcp_streams[session_key]
            
            if direction == 'client_to_server':
                return stream['client_to_server'].data
            elif direction == 'server_to_client':
                return stream['server_to_client'].data
            else:  # both
                # 对于HTTP等协议，可能需要更智能的合并方式
                # 这里简单地按顺序连接
                return {
                    'client_to_server': stream['client_to_server'].data,
                    'server_to_client': stream['server_to_client'].data,
                    'protocol': stream['protocol']
                }
    
    def get_stream_statistics(self, session_key):
        """
        获取流的统计信息
        """
        with self.lock:
            if session_key not in self.tcp_streams:
                return None
                
            stream = self.tcp_streams[session_key]
            return {
                'client': stream['client'],
                'server': stream['server'],
                'protocol': stream['protocol'],
                'client_to_server_bytes': len(stream['client_to_server'].data),
                'server_to_client_bytes': len(stream['server_to_client'].data),
                'client_to_server_packets': stream['client_to_server'].packet_count,
                'server_to_client_packets': stream['server_to_client'].packet_count,
                'out_of_order_packets': (
                    stream['client_to_server'].out_of_order_count +
                    stream['server_to_client'].out_of_order_count
                ),
                'retransmissions': (
                    stream['client_to_server'].retransmissions +
                    stream['server_to_client'].retransmissions
                ),
                'start_time': stream['start_time'],
                'syn_seen': stream['syn_seen'],
                'fin_seen': stream['fin_seen']
            }
    
    def get_all_streams(self):
        """
        获取所有TCP流的摘要信息
        """
        with self.lock:
            summaries = []
            for session_key, stream in self.tcp_streams.items():
                stats = self.get_stream_statistics(session_key)
                summaries.append({
                    'session_key': session_key,
                    'summary': stats
                })
            return summaries


class TCPDirection:
    """
    表示TCP连接的单个方向
    """
    def __init__(self):
        self.data = b''  # 重组后的数据
        self.isn = None  # 初始序列号
        self.next_seq = None  # 期望的下一个序列号
        self.out_of_order_packets = {}  # 乱序包缓冲区 {seq: data}
        self.packet_count = 0  # 包计数
        self.out_of_order_count = 0  # 乱序包计数
        self.retransmissions = 0  # 重传计数


