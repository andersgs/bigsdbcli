'''
A class to generate keys and session for PubMLST
'''

import time
import os
import json
import logging
import urllib
log = logging.getLogger(__name__)

import requests
import toml
from rauth import OAuth1Service,OAuth1Session

class BigsDBOAuth:
    '''
    A class to create sessions, and tokens for interacting with PubMLST
    '''
    def __init__(self, config, store="$HOME/.bigsdb"):
        self._parse_config(config)
        self._create_store(store)
        self.service = OAuth1Service(
                        name = 'BIGSdb',
                        consumer_key = self.CONSUMER_KEY,
                        consumer_secret = self.CONSUMER_SECRET,
                        request_token_url = self.REQUEST_TOKEN_URL,
                        access_token_url = self.ACCESS_TOKEN_URL,
                        base_url = self.REST_URL,
                    )

    def _parse_config(self, config):
        '''
        Given a config file in TOML format, parse the parameters to 
        create the instance.
        '''
        config = toml.load(config)
        self.CONSUMER_KEY = config['keys']["CONSUMER_KEY"]
        self.CONSUMER_SECRET = config['keys']['CONSUMER_SECRET']
        self.REST_URL = config['baseurls']['REST_URL']
        self.WEB_URL = config['baseurls']['WEB_URL']
        self.REQUEST_TOKEN_URL = urllib.parse.urljoin(self.REST_URL, config['routes']['REQUEST_TOKEN_ROUTE'])
        self.ACCESS_TOKEN_URL = urllib.parse.urljoin(self.REST_URL, config['routes']['ACCESS_TOKEN_ROUTE'])
        self.SESSION_TOKEN_URL = urllib.parse.urljoin(self.REST_URL, config['routes']['SESSION_TOKEN_ROUTE'])
        self.AUTHORIZE_URL = urllib.parse.urljoin(self.WEB_URL, config['routes']['AUTHORIZE_ROUTE'])
        self.BIGSDB_INSTANCE = config['bigsdb_instance']
    
    def _create_store(self, store):
        '''
        Create a location to store the OAuth tokens. In general, the idea 
        is to have a store per BigsDB instance (e.g., pubmlst, Pasteur) as
        subfolders of a $HOME/.bigsdb folder. But, the user can change that.
        
        '''
        store = os.path.expandvars(store)
        store = os.path.expanduser(store)
        store = os.path.abspath(store)
        store = os.path.join(store, self.BIGSDB_INSTANCE)
        if not os.path.exists(store):
            os.mkdirs(store)
        self.store = store
        self.request_token_store = os.path.join(self.store, 'request_token.json')
        self.access_token_store = os.path.join(self.store, 'request_access.json')
        self.session_token_store = os.path.join(self.store, 'request_session.json')
    
    def _load_token(self, token_store):
        '''
        Given a token type (request, access, session), load it from the store

        Input:
        ------
        token_store: str (token store location)

        Output:
        ------
        req_store: dict ('oauth_token': xxx, 'oauth_token_secret': xxx) 
        '''
        with open(token_store, 'r') as f:
            req_store = json.load(f)
        return req_store


    def _save_token(self, token_store, req):
        '''
        Given a sucessfull token request, save it to the store

        Input:
        ------
        token: str (token store location)
        req: Request obj (with a 200 status code)

        Output:
        -------
        req: dict
        '''
        req = req.json()
        req.pop('oauth_callback_confirmed', None)
        with open(token_store, "w") as f:
            f.write(json.dumps(req))
        return req

    def _is_token_stale(self,token_store, expiry=12):
        '''
        If a token store was created over expiry hours ago, delete, and restart.

        Input:
        ------
        token_store:
        expiry: int (hours)
        
        Output:
        ------
        is_stale: bool
        '''
        expiry_seconds = expiry * 3600
        stat = os.stat(token_store)
        now = time.time()
        cutoff = now - expiry_seconds
        return stat.st_ctime < cutoff
    
    def _get_token(self, token):
        '''
        Given a token name, return the token value in the obj instance

        Input:
        ------
        token: str (e.g., ACCESS_TOKEN, ACCESS_SECRET)

        Output:
        -------
        token: str (token value, or None)
        '''
        return getattr(self, token, None)

    def get_request_token(self):
        '''
        Fetch a resource token. First step in OAuth authorisation
        '''
        if os.path.exists(self.request_token_store) and not self._is_token_stale(self.request_token_store):
            req_store = self._load_token(self.request_token_store)
        else:
            log.info("Getting a request token...")
            log.debug(self.REQUEST_TOKEN_URL)
            req_store = self.service.get_raw_request_token(params={'oauth_callback':'oob'})
            if req_store.status_code == 200:
                req_store = self._save_token('request', req_store)
            else:
                raise requests.exceptions.HTTPError(req_store.json()['message'])
        self.REQUEST_TOKEN = req_store['oauth_token']
        self.REQUEST_SECRET = req_store['oauth_token_secret']
        log.info("Request token successfully loaded...")

    def get_access_token(self):
        '''
        Fetch an access token. Requires user input...
        '''
        if os.path.exists(self.access_token_store):
            req_store = self._load_token(self.access_token_store)
        else:
            log.info("Getting an access token...")
            log.info("This will require some interaction from the user...")
            request_token = self._get_token('REQUEST_TOKEN')
            request_token_secret = self._get_token(self, 'REQUEST_SECRET')
            if request_token is None or request_token_secret is None:
                self.get_request_token()
            print(f"Log in at {self.AUTHORIZE_URL}&oauth_token={self.REQUEST_TOKEN}")
            verifier = input("Please enter the verification code: ")
            req_store = self.service.get_raw_access_token(self.REQUEST_TOKEN, self.REQUEST_SECRET, params={'oauth_verifier':verifier})
            if req_store.status_code == 200:
                req_store = self._save_token(self.access_token_store, req_store)
            else:
                raise requests.exceptions.HTTPError(req_store.json()['message'])
        self.ACCESS_TOKEN = req_store['oauth_token']
        self.ACCESS_SECRET = req_store['oauth_token_secret']
        log.info("Access token successfully loaded...")
    
    def get_session_token(self):
        '''
        Fetch a session token.
        '''
        if os.path.exists(self.session_token_store) and not self._is_token_stale(self.session_token_store):
            req_store = self._load_token(self.session_token_store)
        else:
            access_token = self._get_token("ACCESS_TOKEN")
            access_secret =  self._get_token("ACCESS_SECRET")
            if access_token is None or access_secret is None:
                self.get_access_token()
            session_request = OAuth1Session(self.CONSUMER_KEY, self.CONSUMER_SECRET,
                                            self.ACCESS_TOKEN, self.ACCESS_SECRET)
            req_store = session_request.get(self.SESSION_TOKEN_URL)
            if req_store.status_code == 200:
                req_store = self._save_token(self.session_token_store, req_store)
            else:
                raise requests.exceptions.HTTPError(req_store.json()['message'])
        self.SESSION_TOKEN = req_store['oauth_token']
        self.SESSION_SECRET = req_store['oauth_token_secret']
        log.info("Session token successfully loaded...")
    

    def _parse_result(self, req):
        '''
        Given a request parse the output according to HTTP status code

        Input:
        -----
        req: a request object created with self.get, self.delete, self. post. 

        Output:
        ------
        Depends on the status code.
        '''

        if req.status_code in [200, 201]:
            log.info("Request successful...")
            return req.json() if 'json' in req.headers['content-type'] else req.text
        if req.status_code == 400:
            log.critical("Bad request!")
            raise requests.exceptions.HTTPError(req.json()['message'])
        if req.status_code == 401:
            if 'unauthorized' in req.json()['message']:
                log.critical("You can't access this resource...")
                raise requests.exceptions.HTTPError(req.json()['message'])
            if 'verification' in req.json()['message']:
                log.info("Found verification in response, return JSON")
                return req.json()
        raise requests.exceptions.HTTPError(req.json()['message'])


    def _check_session(self):
        '''
        Check if a session attribute exists in the current instance
        '''
        if not hasattr(self, 'session'):
            self.create_session()
        return True

    def create_session(self):
        '''
        Create and return an authenticated session ready for use 
        '''
        log.info("Creating a session...")
        self.get_session_token()
        self.session = OAuth1Session(self.CONSUMER_KEY, self.CONSUMER_SECRET,
                                     self.SESSION_TOKEN, self.SESSION_SECRET)
                        
    def get(self, route, params={}):
        '''
        Get a resource from a route
        '''
        self._check_session()
        url = urllib.parse.urljoin(self.REST_URL, route)
        req = self.session.get(url, params=params)
        return self._parse_result(req)

    
    def post(self, route, data={}):
        '''
        Post some data to a route
        '''
        self._check_session()
        url = urllib.parse.urljoin(self.REST_URL, route)
        req = self.session.post(url, data=data)
        return self._parse_result(req)
    
    def delete(self, route):
        '''
        Delete a resource
        '''
        self._check_session()
        url = urllib.parse.urljoin(self.REST_URL, route)
        req = self.session.delete(url)
        return self._parse_result(req)
        


if __name__ == "__main__":
    import pprint
    config = "configs/config_test.toml"
    logging.basicConfig(level=logging.DEBUG)
    pubmlst = BigsDBOAuth(config)
    pubmlst.get_session_token()
    pprint.pprint(pubmlst.get(route="/"))
        