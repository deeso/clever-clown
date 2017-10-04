import dns.rdatatype
from socket import AF_INET as ip4, AF_INET6 as ip6

RECORD_TYPES_ENUMS = {
    dns.rdatatype.A: 'A',
    dns.rdatatype.A6: 'A6',
    dns.rdatatype.AAAA: 'AAAA',
    dns.rdatatype.AFSDB: 'AFSDB',
    dns.rdatatype.ANY: 'ANY',
    dns.rdatatype.APL: 'APL',
    dns.rdatatype.AVC: 'AVC',
    dns.rdatatype.AXFR: 'AXFR',
    dns.rdatatype.CAA: 'CAA',
    dns.rdatatype.CDNSKEY: 'CDNSKEY',
    dns.rdatatype.CDS: 'CDS',
    dns.rdatatype.CERT: 'CERT',
    dns.rdatatype.CNAME: 'CNAME',
    dns.rdatatype.CSYNC: 'CSYNC',
    dns.rdatatype.DHCID: 'DHCID',
    dns.rdatatype.DLV: 'DLV',
    dns.rdatatype.DNAME: 'DNAME',
    dns.rdatatype.DNSKEY: 'DNSKEY',
    dns.rdatatype.DS: 'DS',
    dns.rdatatype.EUI48: 'EUI48',
    dns.rdatatype.EUI64: 'EUI64',
    dns.rdatatype.GPOS: 'GPOS',
    dns.rdatatype.HINFO: 'HINFO',
    dns.rdatatype.HIP: 'HIP',
    dns.rdatatype.IPSECKEY: 'IPSECKEY',
    dns.rdatatype.ISDN: 'ISDN',
    dns.rdatatype.IXFR: 'IXFR',
    dns.rdatatype.KEY: 'KEY',
    dns.rdatatype.KX: 'KX',
    dns.rdatatype.LOC: 'LOC',
    dns.rdatatype.MAILA: 'MAILA',
    dns.rdatatype.MAILB: 'MAILB',
    dns.rdatatype.MB: 'MB',
    dns.rdatatype.MD: 'MD',
    dns.rdatatype.MF: 'MF',
    dns.rdatatype.MG: 'MG',
    dns.rdatatype.MINFO: 'MINFO',
    dns.rdatatype.MR: 'MR',
    dns.rdatatype.MX: 'MX',
    dns.rdatatype.NAPTR: 'NAPTR',
    dns.rdatatype.NONE: 'NONE',
    dns.rdatatype.NS: 'NS',
    dns.rdatatype.NSAP: 'NSAP',
    dns.rdatatype.NSAP_PTR: 'NSAP_PTR',
    dns.rdatatype.NSEC: 'NSEC',
    dns.rdatatype.NSEC3: 'NSEC3',
    dns.rdatatype.NSEC3PARAM: 'NSEC3PARAM',
    dns.rdatatype.NULL: 'NULL',
    dns.rdatatype.NXT: 'NXT',
    dns.rdatatype.OPT: 'OPT',
    dns.rdatatype.PTR: 'PTR',
    dns.rdatatype.PX: 'PX',
    dns.rdatatype.RP: 'RP',
    dns.rdatatype.RRSIG: 'RRSIG',
    dns.rdatatype.RT: 'RT',
    dns.rdatatype.SIG: 'SIG',
    dns.rdatatype.SOA: 'SOA',
    dns.rdatatype.SPF: 'SPF',
    dns.rdatatype.SRV: 'SRV',
    dns.rdatatype.SSHFP: 'SSHFP',
    dns.rdatatype.TA: 'TA',
    dns.rdatatype.TKEY: 'TKEY',
    dns.rdatatype.TLSA: 'TLSA',
    dns.rdatatype.TSIG: 'TSIG',
    dns.rdatatype.TXT: 'TXT',
    dns.rdatatype.UNSPEC: 'UNSPEC',
    dns.rdatatype.URI: 'URI',
    dns.rdatatype.WKS: 'WKS',
    dns.rdatatype.X25: 'X25',
}

RECORD_TYPES = {
    'A': dns.rdatatype.A,
    'A6': dns.rdatatype.A6,
    'AAAA': dns.rdatatype.AAAA,
    'AFSDB': dns.rdatatype.AFSDB,
    'ANY': dns.rdatatype.ANY,
    'APL': dns.rdatatype.APL,
    'AVC': dns.rdatatype.AVC,
    'AXFR': dns.rdatatype.AXFR,
    'CAA': dns.rdatatype.CAA,
    'CDNSKEY': dns.rdatatype.CDNSKEY,
    'CDS': dns.rdatatype.CDS,
    'CERT': dns.rdatatype.CERT,
    'CNAME': dns.rdatatype.CNAME,
    'CSYNC': dns.rdatatype.CSYNC,
    'DHCID': dns.rdatatype.DHCID,
    'DLV': dns.rdatatype.DLV,
    'DNAME': dns.rdatatype.DNAME,
    'DNSKEY': dns.rdatatype.DNSKEY,
    'DS': dns.rdatatype.DS,
    'EUI48': dns.rdatatype.EUI48,
    'EUI64': dns.rdatatype.EUI64,
    'GPOS': dns.rdatatype.GPOS,
    'HINFO': dns.rdatatype.HINFO,
    'HIP': dns.rdatatype.HIP,
    'IPSECKEY': dns.rdatatype.IPSECKEY,
    'ISDN': dns.rdatatype.ISDN,
    'IXFR': dns.rdatatype.IXFR,
    'KEY': dns.rdatatype.KEY,
    'KX': dns.rdatatype.KX,
    'LOC': dns.rdatatype.LOC,
    'MAILA': dns.rdatatype.MAILA,
    'MAILB': dns.rdatatype.MAILB,
    'MB': dns.rdatatype.MB,
    'MD': dns.rdatatype.MD,
    'MF': dns.rdatatype.MF,
    'MG': dns.rdatatype.MG,
    'MINFO': dns.rdatatype.MINFO,
    'MR': dns.rdatatype.MR,
    'MX': dns.rdatatype.MX,
    'NAPTR': dns.rdatatype.NAPTR,
    'NONE': dns.rdatatype.NONE,
    'NS': dns.rdatatype.NS,
    'NSAP': dns.rdatatype.NSAP,
    'NSAP_PTR': dns.rdatatype.NSAP_PTR,
    'NSEC': dns.rdatatype.NSEC,
    'NSEC3': dns.rdatatype.NSEC3,
    'NSEC3PARAM': dns.rdatatype.NSEC3PARAM,
    'NULL': dns.rdatatype.NULL,
    'NXT': dns.rdatatype.NXT,
    'OPT': dns.rdatatype.OPT,
    'PTR': dns.rdatatype.PTR,
    'PX': dns.rdatatype.PX,
    'RP': dns.rdatatype.RP,
    'RRSIG': dns.rdatatype.RRSIG,
    'RT': dns.rdatatype.RT,
    'SIG': dns.rdatatype.SIG,
    'SOA': dns.rdatatype.SOA,
    'SPF': dns.rdatatype.SPF,
    'SRV': dns.rdatatype.SRV,
    'SSHFP': dns.rdatatype.SSHFP,
    'TA': dns.rdatatype.TA,
    'TKEY': dns.rdatatype.TKEY,
    'TLSA': dns.rdatatype.TLSA,
    'TSIG': dns.rdatatype.TSIG,
    'TXT': dns.rdatatype.TXT,
    'UNSPEC': dns.rdatatype.UNSPEC,
    'URI': dns.rdatatype.URI,
    'WKS': dns.rdatatype.WKS,
    'X25': dns.rdatatype.X25,
}


def get_addr_family(af_str):
    if af_str == 'ipv6':
        return ip6
    else:
        return ip4


def get_record_type(rt):
    return RECORD_TYPES.get(rt, None)


def get_record_str(rt_num):
    return RECORD_TYPES_ENUMS.get(rt_num, None)


def get_basic_message(domain_name, query_type='A', qid=None):
    if query_type not in RECORD_TYPES:
        return None
    qname = dns.name.from_text(domain_name)
    q = dns.message.make_query(qname, RECORD_TYPES.get(query_type))
    if isinstance(qid, int) or isinstance(qid, long):
        q.id = qid
    return q


def basic_udp_query(domain_name, query_type, dns_server, dns_port,
                    af='ipv4', qid=None):
    q = get_basic_message(domain_name, query_type, qid=qid)
    if q is None:
        return None
    return dns.query.udp(q, dns_server, port=dns_port, af=get_addr_family(af))


def basic_tcp_query(domain_name, query_type, dns_server, dns_port,
                    af='ipv4', qid=None):
    q = get_basic_message(domain_name, query_type, qid=qid)
    if q is None:
        return None
    return dns.query.tcp(q, dns_server, port=dns_port, af=get_addr_family(af))
