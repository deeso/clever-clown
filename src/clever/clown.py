from kombu import Connection
from .resolver_types import RESOVLER_TYPE_MAP
from .resolver_types import DnsService

import toml
import os
import socketserver
import logging


class ClownFactory(object):

    REQUIRED_BLOCKS = ['dnstap', 'dnsproviders']
    REQUIRED_DNSTAP = ['dns_host', 'dns_port']

    @classmethod
    def parse(cls, config_file):
        try:
            os.stat(config_file)
        except:
            raise

        config_dict = toml.load(config_file)
        # TODO parse the dnstap configs

        # TODO parse the subscribers and publishers

        # TODO parse the DNS providers

        # TODO parse the logging setup

        # TODO create the clever-clown service

        return ClownService()


class ClownService(object):
    DEFAULT_NAME = 'clever-clown'
    DEFAULT_RESOLVER = 'Google'
    DEFAULT_HOST='0.0.0.0'
    DEFAULT_PORT=53530

    DEFAULT_RESOLVER = 'Google'
    GV6 = '2001:4860:4860:0:0:0:0:8888'
    GV4 = '8.8.8.8'
    RESOLVERS = {DEFAULT_RESOLVER: DnsService(DEFAULT_RESOLVER, GV4)}
    RESOLVERS_64 = {DEFAULT_RESOLVER: DnsServicev6(DEFAULT_RESOLVER, GV6)}

    def __init__(self, name=DEFAULT_NAME, default_responder=DEFAULT_RESOLVER,
                 default_responder_64=DEFAULT_RESOLVER, query_response=False,
                 enabled_responders=[DEFAULT_RESOLVER, ],
                 enabled_responders_64=[DEFAULT_RESOLVER, ],
                 dns_host=DEFAULT_PORT, dns_port=DEFAULT_HOST,
                 dns_providers={}, publishers={}, subscripers={},
                 query_limit_per_pub=10):

        self.dns_host = dns_host
        self.dns_port = dns_port

        self.subscripers = subscripers
        self.publishers = publishers

        self.enabled_responders = enabled_responders
        if len(enabled_responders) == 0:
            self.enabled_responders.append(DEFAULT_RESOLVER)

        self.enabled_responders_64 = enabled_responders
        if len(enabled_responders_64) == 0:
            self.enabled_responders_64.append(DEFAULT_RESOLVER)

        self.tcpclown = TCPClown(listen_port=dns_port, listen_host=dns_host)
        self.udpclown = UDPClown(listen_port=dns_port, listen_host=dns_host)
        self.query_limit_per_pub = query_limit_per_pub

    def consumer_callback(self, pub, msg):
        # TODO extract the domain name or IP address to look up

        # TODO For each DNS service process the domain and save the results
        if 'domains' in msg:
            for d in msg['domains']:
                pass

    def consume(self):
        # TODO iterate through all of the publishers and pull off N messages
        # and process them with the callback
        query_results = {}
        for name, publisher in list(self.publisher.items()):
            queries = publisher.recv_messages(cnt=self.query_limit_per_pub,
                                              callback=self.consumer_callback)
            query_results[name] = queries
        return query_results

    def publish(self, results):
        # TODO publish query results to all relevant subscribers
        pass

class Clown(socketserver.BaseRequestHandler):
    DEFAULT_RESOLVER = 'Google'
    RESOLVERS = {'Google': DnsService('google', '8.8.8.8')}
    LISTEN_PORT = 5454
    STORE_URI = "redis://127.0.0.1:6379"
    STORE_QUEUE = "clever-clown-results"
    RESPOND_TO_REQUEST = False


    @classmethod
    def configure(cls, default_resolver=DEFAULT_RESOLVER,
                  default_resolvers=RESOLVERS,
                  store_uri=STORE_URI,
                  store_queue=STORE_QUEUE, **kargs):
        cls.LISTEN_PORT = kargs.get('listen_port', 5454)
        cls.STORE_URI = store_uri
        cls.STORE_QUEUE = store_queue
        cls.DEFAULT_RESOLVER = default_resolver

        for name, resolver in kargs.get('resolvers', []):
            name = resolver.get('name', None)
            type_ = resolver.get('type_', None)

            if name is None or type_ is None:
                raise Exception("Resolver name and type need to be set")

            r_cls = RESOVLER_TYPE_MAP.get(type_, None)

            if r_cls is None:
                raise Exception("Invalid resolver specified")

            r = r_cls(**resolver)
            cls.RESOLVERS[name] = r

        if cls.DEFAULT_RESOLVER not in cls.RESOLVERS:
            n = list(cls.RESOLVERS.keys())[0]
            cls.DEFAULT_RESOLVER = n

    def handle(self):
        host = self.client_address[0]
        logging.debug("Handling request from %s" % host)
        self.data = self.recv_request(self.request)

        # send requests out to each resolver
        responses = self.resolve_requests(self.data)

        # etl response data
        etl_data = self.response_etl(responses)

        # send the data to logs
        self.store_kombu(etl_data)

        #  TODO forward response to client
        # XXX XXX XXX XXX

    def resolve_requests(self, data):
        # extract the specific DNS request
        responses = {}
        for r in self.RESOLVERS:
            # wait for response?
            response = r.send_request(data)
            responses[r.name] = response
        return responses

    def response_etl(self, responses):
        etl = {}
        for name, response in list(responses.items()):
            response_json = response.to_json()
            for k, v in list(response_json.items()):
                etl_key = '%s_%s' % (name, k)
                etl[etl_key] = v
        return etl

    def store_kombu(self, etl_data):
        logging.debug("Storing message in logstash queue")
        try:
            with Connection(self.STORE_URI) as conn:
                q = conn.SimpleQueue(self.STORE_URI)
                q.put(json.dumps(etl_data))
                q.close()
        except:
            logging.debug("Storing message done")

    def read_data(self):
        raise Exception("Not implemented")


class TCPClown(Clown):
    @classmethod
    def recv_request(cls, sock):
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
        self.data = data
        return data

    @classmethod
    def send_data(cls, client, sock, data):
        return sock.sendall(data)


class UDPClown(Clown):
    @classmethod
    def recv_request(cls, sock):
        return sock[0]

    @classmethod
    def send_data(cls, client, sock, data):
        return sock.sendto(data, client)
