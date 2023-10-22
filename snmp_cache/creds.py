'''
Credential objects
'''
from puresnmp import V2C, V3

class SnmpCredV2:
    ''' Class to represent an SNMP v2 credential '''
    def __init__(self, community:str):
        self.community = community

    def __str__(self):
        ''' Return the credential information as a printable string '''
        return f"SNMPv2 community: {self.community}"

    @property
    def creds(self) -> V2C:
        ''' Returns the puresnmp cred object '''
        return V2C(community=self.community)

AUTH_NONE = None
AUTH_MD5 = 'md5'
AUTH_SHA1 = 'sha1'
AUTH_SUPPORTED = [AUTH_NONE, AUTH_MD5, AUTH_SHA1]

PRIV_NONE = None
PRIV_DES = 'des'
PRIV_AES_128 = 'aes'
PRIV_SUPPORTED = [PRIV_NONE, PRIV_DES, PRIV_AES_128]


class SnmpCredV3:
    '''' Class to represent an SNMP v2 credential '''
    def __init__(self, user:str, auth=AUTH_NONE, auth_pass=None, priv=PRIV_NONE, priv_pass=None):
        self.user = user
        self.auth = None if not isinstance(auth, str) or auth == '' else auth
        self.auth_pass = None if not isinstance(auth_pass, str) or auth_pass == '' else auth_pass
        self.priv = None if not isinstance(priv, str) or priv == '' else priv
        self.priv_pass = None if not isinstance(priv_pass, str) or priv_pass == '' else priv_pass

        # check parameters
        if len(user) == 0:
            raise ValueError("Username missing!")
        if self.auth not in AUTH_SUPPORTED:
            raise ValueError(f'Unsupported authentication type "{self.auth}"! Supported list: {AUTH_SUPPORTED}')
        if self.priv not in PRIV_SUPPORTED:
            raise ValueError(f'Unsupported priv type "{self.priv}"! Supported priv: {PRIV_SUPPORTED}')
        if self.auth is not None and (not isinstance(self.auth_pass, str) or not len(self.auth_pass) > 0):
            raise ValueError(f'Auth type {self.auth} provided but no password!')
        if self.priv is not None and (not isinstance(self.priv_pass, str) or not len(self.priv_pass) > 0):
            raise ValueError(f'Priv type {self.priv} provided but no password!')

    def __str__(self):
        ''' Return the credential information as a printable string '''
        return f"SNMPv3 user: {self.user} Auth: {self.auth} Priv: {self.priv}" 

    @property
    def creds(self) -> V3:
        ''' Retuns puresnmp cred object '''
        cred_data = {'username': self.user}
        if self.auth in AUTH_SUPPORTED and self.auth is not None and self.auth_pass is not None:
            cred_data['auth'] = Auth(key=self.auth_pass.encode(), method=self.auth) # type: ignore
        if self.priv in PRIV_SUPPORTED and self.priv is not None and self.priv_pass is not None:
            cred_data['priv'] = Priv(key=self.priv_pass.encode(), method=self.priv) # type: ignore
        return puresnmp.V3(**cred_data) # type: ignore