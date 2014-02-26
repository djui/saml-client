SAML Client
===========

Python class to fetch a website behind a SAML2 SSO service conforming to the
Shibboleth protocol.

Usage
=====

```python
import saml

client = saml.Client(username, password)
```

Examples
========

```python
>>> import saml
>>> client = saml.Client()
>>> client.dump('http://www.example.com')
Authentication required. Credentials are stored in OS keychain/keyring
Username:
Password:
```

```python
>>> import saml
>>> client = saml.Client(username, password)
>>> print(client.dump('http://www.example.com'))
```

```python
>>> import pickle
>>> import saml
>>> client = saml.Client(username, password)
>>> pickle.dump(client.get('http://www.example.com'), open('index.html'))
```
