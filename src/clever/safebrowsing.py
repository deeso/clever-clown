from gglsbl import SafeBrowsingList
from urllib.parse import urlparse
import os


class SafeBrowsing(object):
    TYPE = "GoogleSBCheck"
    CP_FMT = '{scheme}://{netloc}/{path}'

    def __init__(self, name=None, api_key=None,
                 db_path='/tmp/gsb_4.db', update_hash_prefix_cache=False):
        self.api_key = api_key
        self.db_path = db_path

        self.sbl = SafeBrowsingList(api_key, db_path=db_path)
        self.update_hash_prefix_cache = update_hash_prefix_cache
        try:
            os.stat(db_path)
        except:
            self.update_hash_prefix_cache = True

        if self.update_hash_prefix_cache:
            # this may take a while so be patient (over 1600MB of data)
            self.sbl.update_hash_prefix_cache()

    def is_blacklisted(self, url):
        return not SafeBrowsing.thread_safe_lookup(url) is None

    def lookup_url(self, url):
        up = urlparse(url)
        cp = self.CP_FMT.format(**{'scheme': up.scheme,
                                   'netloc': up.netloc,
                                   'path': up.path}).strip('/')+'/'
        return self.sbl.lookup_url(cp)

    def handle_domain(self, domain):
        return self.handle_domains([domain, ])

    def handle_domains(self, domains):
        results = {}
        for domain in domains:
            t = "https://" + domain
            u = "http://" + domain
            results[domain] = False
            if self.lookup_url(t) or self.lookup_url(u):
                results[domain] = True
                continue
        return results
