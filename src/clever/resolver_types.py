from .safebrowsing import SafeBrowsing
import logging
import socket
import dnslib

RESOVLER_TYPE_MAP = {}

UDP = 'UDP'
TCP = 'TCP'
DNS = 'DNS'
EDNS = 'EDNS0TLV'
TRANSPORT = ['sport', 'dport', 'len']


class DnsServicev4(object):
    TYPE = "dnsservicev4"

    def __init__(self, name=None, server_address=None,
                 server_port=53, safe_browsing=None):
        self.name = name
        self.server_address = server_address
        self.server_port = server_port
        self.sbl = safe_browsing

    def check_domains(self, domains):
        results = {}
        _safe_domains = sbl.handle_domains(domains)
        for k, v in _safe_domains.items():
            results[k] = 'safe_domain' if v else 'unsafe_domain'
        return results

    def is_edns(self, data):
        try:
            dnslib.DNSRecord.parse(data)
            return False
        except:
            return True

    def handle(self, req_data, traffic_type):
        dns_etl_data = self.serialize_dns(req_data, prepend='req')
        dns_etl_data['req_len'] = len(req_data)
        dns_etl_data['req_type'] = 'dns' if self.is_edns(req_data) else 'edns'

        rsp_data = self.send_request(req_data, traffic_type)
        rsp_etl_data = self.serialize_dns(rsp_data, prepend='rsp')
        rsp_etl_data['rsp_len'] = len(rsp_data)
        dns_etl_data.update(rsp_etl_data)
        hosts = [i['qname'].strip('.') for i in dns_etl_data['req_questions'] if 'qname' in i]
        hosts = hosts + \
                [i['rname'].strip('.') for i in dns_etl_data['rsp_responses'] if 'rname' in i]
        return rsp_data, dns_etl_data

    def send_request(self, req_data, traffic_type):
        if traffic_type == 'udp':
            return self.send_udp(req_data)
        else:
            return self.send_tcp(req_data)

    def send_udp(self, packet_data):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(packet_data, (self.server_address, self.server_port))
        recv_data = s.recvfrom(8192)
        return recv_data

    def send_tcp(self, packet_data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server_address, self.server_port))
        data = sock.recv(8192)
        if len(data) < 2:
            raise Exception("Packet size too small")

        sz = int(data[:2].encode('hex'), 16)

        if sz > len(data) - 2:
            while True:
                if sz > len(data) - 2:
                    tmp = sock.recv(sz-len(data)-2)
                    if tmp == '':
                        break
                    data = data + tmp

        if sz < len(data) - 2:
            logging.debug("TCP packet under the specified size")
            raise Exception("TCP packet under the specified size")
        elif sz > len(data) - 2:
            logging.debug("TCP packet over the specified size")
            raise Exception("TCP packet over the specified size")
        return data

    def serialize_dns(self, data, prepend=''):
        etl = {}
        dns_req = dnslib.EDNS0.parse(data)

        nkey = 'header' if prepend == '' else prepend+'_header'
        etl[nkey] = {}
        header = repr(dns_req.header).strip('<DNS Header: ').strip('>').strip()
        for e in header.split():
            k, v = e.strip().split('=')
            etl[nkey][k] = v.replace("'", '')

        nkey = 'questions' if prepend == '' else prepend+'_questions'
        etl[nkey] = []
        for question in dns_req.questions:
            msg = {}
            for k, v in question.__dict__.items():
                msg[k.strip('_')] = str(v)
            etl[nkey].append(msg)

        nkey = 'responses' if prepend == '' else prepend+'_responses'
        etl[nkey] = []
        for response in dns_req.rr:
            msg = {}
            for k, v in response.__dict__.items():
                msg[k.strip('_')] = str(v)
            etl[nkey].append(msg)
        return etl

        nkey = 'ar' if prepend == '' else prepend+'_ar'
        etl[nkey] = []
        for response in dns_req.ar:
            msg = {}
            for k, v in response.__dict__.items():
                msg[k.strip('_')] = str(v)
            etl[nkey].append(msg)
        return etl

        nkey = 'auth' if prepend == '' else prepend+'_auth'
        etl[nkey] = []
        for response in dns_req.auth:
            msg = {}
            for k, v in response.__dict__.items():
                msg[k.strip('_')] = str(v)
            etl[nkey].append(msg)
        return etl
