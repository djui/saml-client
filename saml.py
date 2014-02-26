from __future__ import print_function

import cookielib
import getpass
import HTMLParser
import re
import sys
import urllib
import urllib2


class Client:
  """Minimal implementation of http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
  guided by http://dev.e-taxonomy.eu/trac/wiki/ShibbolethProtocol

  Authentication is done lazily. If no username nor password is provided and no
  authentication is required, the request succeeds without interruption. If
  authentication is required, the request gets interrupted in case no username
  and password was given during instatiation, prompting for credentials.
  """
  def __init__(self, username=None, password=None):
    # Create (global) cookie jar. Works across multiple requests
    cj = cookielib.CookieJar()
    self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    self.username = username or getpass.getuser()
    self.password = password


  def get(self, url):
    # 1. Request target resource
    # 2. Redirect to SSO Service
    res = self.opener.open(url)

    # Already logged in? (directly got to requesting page)
    if res.geturl() == url:
      return res

    # Prepare authentication payload. Implementation specific!
    self.ensure_credentials()
    auth_url  = res.geturl()
    auth_data = urllib.urlencode({
      'j_username': self.username,
      'j_password': self.password
    })

    # 3. Request SSO Service
    # 4. Respond with XHTML form
    res = self.opener.open(auth_url, auth_data)

    # Authentication failed? (staying on same page)
    if res.geturl() == auth_url:
      raise urllib2.HTTPError(auth_url, 401, 'Authentication failed', res.info(), res)

    # Prepare assertion payload. Implementation specific!
    content = res.read()

    html_parser = HTMLParser.HTMLParser()
    assertion_url_regex = re.compile('<form action="(.*?)" method="post">')
    relay_state_regex   = re.compile('<input type="hidden" name="RelayState" value="(.*?)"/>')
    saml_response_regex = re.compile('<input type="hidden" name="SAMLResponse" value="(.*?)"/>')
    assertion_url_match = assertion_url_regex.search(content)
    relay_state_match   = relay_state_regex.search(content)
    saml_response_match = saml_response_regex.search(content)
    assertion_url       = html_parser.unescape(assertion_url_match.group(1))
    relay_state         = html_parser.unescape(relay_state_match.group(1))
    saml_response       = saml_response_match.group(1)
    saml_data = urllib.urlencode({
      'RelayState': relay_state,
      'SAMLResponse': saml_response
    })

    # 5. Request Assertion Consumer Service
    # 6. Redirect to target resource
    # 7. Request target resource
    # 8. Respond with requested resource
    return self.opener.open(assertion_url, saml_data)


  def dump(self, url):
    f = self.get(url)
    data = f.read()
    f.close()
    return data


  def ensure_credentials(self):
    # Load lazily in case it's not needed
    try:
      import keyring
    except ImportError as e:
      print('Dependency missing. Try `pip install keyring`', file=sys.stderr)
      raise e

    if self.username == None and sys.stdin.isatty() and sys.stdout.isatty():
      print('Authentication required. Credentials are stored in OS keychain/keyring')
      self.username = raw_input('Username: ')

    if self.password == None:
      keyring_service = 'rieplay'
      self.password = keyring.get_password(keyring_service, self.username)
      if self.password == None and sys.stdin.isatty() and sys.stdout.isatty():
        self.password = getpass.getpass('Password: ')
        keyring.set_password(keyring_service, self.username, self.password)
