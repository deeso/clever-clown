from .safebrowsing import SafeBrowsing
import logging
import socket
import dns.resolver


class DnsService(object):
    TYPE = "dnsservicev4"

    def __init__(self, name=None, server_address=None,
                 server_port=53, safe_browsing=None):
        self.name = name
        self.server_address = server_address
        self.server_port = server_port
        self.sbl = safe_browsing

    def perform_query(self, qname, rdtype, qproto='udp'):
        return self.resolver.resolve(qname, rdtype, tcp=(qproto == 'tcp'))

    @classmethod
    def process_easyway(cls, answers):
        response = {'questions': [], 'answers': [], 'additionals': [],
                    'rips': [], 'rnames':  [], 'qips': [], 'qnames': [],
                    'raips': [], 'ranames': []}
        lines = [i.strip() for i in str(answers.response).splitlines()]
        processing_question = False
        processing_answers = False
        processing_additional = False
        for line in lines:
            if line.find('id ') == 0:
                response['id'] = int(line.split()[1])
                continue
            elif line.find('opcode ') == 0:
                response['opcode'] = line.split()[1]
                continue
            elif line.find('flags ') == 0:
                response['flags'] = line.split()[1:]
                continue
            elif line.find(';QUESTION') == 0:
                processing_question = True
                continue
            elif line.find(';ANSWER') == 0:
                processing_question = False
                processing_answers = True
                continue
            elif line.find(';ADDITIONAL') == 0:
                processing_answers = False
                processing_additional = True
                continue

            if processing_question:
                elements = line.split()
                # FIXME bad comparison here
                if elements[0].find('ip6.arpa.') > 0 and\
                   elements[-1] == 'PTR':
                    elements[0] = cls.convert_v6(elements[0])
                    response['qips'].append(elements[0])
                elif elements[0].find('.in-addr.arpa') > 0 and \
                     elements[-1] == 'PTR':
                    elements[0] = cls.convert_v4(elements[0])
                    response['qips'].append(elements[0])
                else:
                    response['qips'].append(elements[0].strip('.'))
                response['questions'].append(elements)
            if processing_answers:
                elements = line.split()
                # FIXME bad comparison here
                if elements[0].find('ip6.arpa.') > 0 and\
                   elements[-1] == 'PTR':
                    elements[0] = cls.convert_v6(elements[0])
                    response['rips'].append(elements[0])
                elif elements[0].find('.in-addr.arpa') > 0 and \
                     elements[-1] == 'PTR':
                    elements[0] = cls.convert_v4(elements[0])
                    response['rips'].append(elements[0])
                else:
                    response['rnames'].append(elements[0].strip('.'))
                response['answers'].append(elements)
            if processing_additional:
                elements = line.split()
                # FIXME bad comparison here
                if elements[0].find('ip6.arpa.') > 0 and\
                   elements[-1] == 'PTR':
                    elements[0] = cls.convert_v6(elements[0])
                    response['raips'].append(elements[0])
                elif elements[0].find('.in-addr.arpa') > 0 and \
                   elements[-1] == 'PTR':
                    elements[0] = cls.convert_v4(elements[0])
                    response['raips'].append(elements[0])
                else:
                    response['ranames'].append(elements[0].strip('.'))
                response['additionals'].append(elements)
        return results

    @classmethod
    def convert_v4(self, ip4_reverse):
        ip4 = ip4_reverse.split('.in-addr.arpa')[0].split('.')[::-1]
        return ".".join(ip4)

    @classmethod
    def convert_v6(self, ip6_reverse):
        ip6 = ip6_reverse.split('ip6.arpa.')[0].replace('.', '')[::-1]
        pos = 0
        v = []
        while pos < len(ip6):
            v.append(ip6[pos:pos+4])
            pos += 4
        return ":".join(v)

    def handle_client_request_udp(self, req_data):
        query = dns.message.from_wire(req_data)
        answers = dns.query.udp(query, self.server_address,
                                port=self.server_port)
        results = self.process_easyway(answers)
        results['query_server'] = self.server_address
        results['query_port'] = self.server_port
        return results, answers

    def handle_client_request_tcp(self, req_data):
        query = dns.message.from_wire(req_data)
        answers = dns.query.tcp(query, self.server_address,
                                port=self.server_port)
        results = self.process_easyway(answers)
        results['query_server'] = self.server_address
        results['query_port'] = self.server_port
        return results, answers

    def handle_publisher_request(self, qname, rdtype, qproto='udp'):
        answers = self.resolver.resolve(qname, rdtype, tcp=(qproto == 'tcp'))
        results = self.process_easyway(answers)
        results['query_server'] = self.server_address
        results['query_port'] = self.server_port
        return results, answers

    def check_domains(self, domains):
        results = {}
        _safe_domains = self.sbl.handle_domains(domains)
        for k, v in list(_safe_domains.items()):
            results[k] = 'safe_domain' if v else 'unsafe_domain'
        return results
