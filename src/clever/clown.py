from kombu import Connection
from .resolver_types import RESOVLER_TYPE_MAP
from .resolver_types import DnsServicev4

import toml
import os
import SocketServer
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

    @classmethod
    def contains_valid_blocks(cls, config_dict):



class Clown(SocketServer.BaseRequestHandler):
    DEFAULT_RESOLVER = 'Google'
    RESOLVERS = {'Google': DnsServicev4('google', '8.8.8.8')}
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
            n = cls.RESOLVERS.keys()[0]
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
        for name, response in responses.items():
            response_json = response.to_json()
            for k, v in response_json.items():
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
