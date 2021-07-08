#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from requests_oauthlib import OAuth2Session
from django.core.exceptions import PermissionDenied

from . import oauth_settings
from .openid import (
    jwt_token_noverify,
    jwt_token_verify,
    openid_connect_urls,
)


logger = logging.getLogger(__name__)

USERAGENT = 'OMERO.oauth'


def providers():
    ps = []
    for cfg in oauth_settings.OAUTH_PROVIDERS['providers']:
        try:
            ps.append((cfg['name'], cfg['displayname']))
        except KeyError:
            ps.append((cfg['name'], cfg['name']))
    return ps

class OauthException(Exception):
    def __init__(self, message):
        self.message = message

class OauthProvider(object):

    def __init__(self, name, **kwargs):
        """
        Create an OAuth2Session
        :param name: The OAuth provider name
        :param kwargs: Additional keyword arguments passed to OAuth2Session
        """
        self.name = name
        for item in oauth_settings.OAUTH_PROVIDERS['providers']:
            if item['name'] == name:
                cfg = item
                break
        else:
            raise ValueError('No configuration found for: {}'.format(name))
        self.cfg = cfg
        self._get_urls()
        self.oauth = OAuth2Session(self.get('client.id'),
                                   scope=self.get('client.scopes'),
                                   redirect_uri=self.get('url.callback'),
                                   **kwargs)

    def get(self, keypath, default=None, raise_on_missing=False):
        keys = keypath.split('.')
        v = self.cfg
        for key in keys:
            try:
                v = v[key]
            except KeyError:
                if raise_on_missing:
                    raise KeyError(
                        'Missing configuration property {}'.format(keypath))
                return default
        return v

    def set(self, keypath, value):
        keys = keypath.split('.')
        v = self.cfg
        for key in keys[:-1]:
            try:
                v = v[key]
            except KeyError:
                v[key] = {}
        v[keys[-1]] = value

    def _get_urls(self):
        authorization_url = self.get('url.authorisation')
        token_url = self.get('url.token')
        userinfo_url = self.get('url.userinfo')
        if not all((authorization_url, token_url, userinfo_url)):
            authorization_oid, token_oid, userinfo_oid = openid_connect_urls(
                self.get('openid.issuer', raise_on_missing=True))
            if not authorization_url:
                self.set('url.authorisation', authorization_oid)
            if not token_url:
                self.set('url.token', token_oid)
            if not userinfo_url:
                self.set('url.userinfo', userinfo_oid)

    def authorization(self):
        authorization_url, state = self.oauth.authorization_url(
            self.get('url.authorisation'),
            **self.get('authorization.params', {}))
        return authorization_url, state

    def token(self, code):
        token = self.oauth.fetch_token(
            self.get('url.token'), client_secret=self.get('client.secret'),
            code=code)
        return token

    # user information

    def _expand_template(self, name, args):
        template = self.get('user.{}'.format(name))
        # Replace None with ''
        args = dict((k, v if v is not None else '') for k, v in list(args.items()))
        return template.format(**args)

    def _expand_all(self, args):
        omename = self._expand_template('name', args)
        email = self._expand_template('email', args)
        firstname = self._expand_template('firstname', args)
        lastname = self._expand_template('lastname', args)
        return omename, email, firstname, lastname, None

    def get_userinfo(self, token):
        userinfo_type = self.get('userinfo.type', 'default')
        f = getattr(self, 'userinfo_{}'.format(userinfo_type))
        userinfo_url = self.get('url.userinfo')
        userinfo = f(token, userinfo_url)
        return userinfo

    def userinfo_default(self, token, userinfo_url):
        userinfo = self.oauth.get(userinfo_url).json()
        logger.debug('Got raw userinfo %s', userinfo)
        return self._expand_all(userinfo)

    def userinfo_synapse(self, token, userinfo_url):
        decoded = jwt_token_noverify(token['id_token'])
        teams = decoded.get("team", [])
        if len(teams) == 0:
            raise OauthException('Required team not found, request membership from your Synapse team manager.')
        return self._expand_all(decoded)

    def userinfo_synapse_idp(self, token, userinfo_url):
        decoded = jwt_token_noverify(token['id_token'])
        teams = decoded.get("team", [])
        if len(teams) == 0:
            raise OauthException('Required team not found, request membership from your Synapse team manager.')
        userinfo = list(self._expand_all(decoded))
        # Hard code the team-to-group mapping here. Not ideal.
        if "3429409" in teams:
            userinfo[4] = "Ludwig"
        else:
            userinfo[4] = "HTAN"
        return tuple(userinfo)

    def userinfo_github(self, token, userinfo_url):
        # Note userinfo_default() will work if the user's email is public
        # otherwise we need another API call:
        # https://stackoverflow.com/a/35387123/8062212
        userinfo = self.oauth.get(userinfo_url).json()
        logger.debug('Got GitHub userinfo %s', userinfo)
        emailinfo = self.oauth.get(userinfo_url + '/emails').json()
        logger.debug('Got GitHub emails %s', emailinfo)

        omename = self._expand_template('name', userinfo)
        ghname = userinfo['name'].split()
        firstname = ghname[0]
        lastname = ghname[-1]
        try:
            email = [e for e in emailinfo if e['primary']][0]['email']
        except IndexError:
            email = self._expand_template('email', userinfo)
        return omename, email, firstname, lastname, None

    def userinfo_orcid(self, token, userinfo_url):
        from xml.etree import ElementTree

        userinfo = self.oauth.get(userinfo_url.format(**token))
        logger.debug('Got ORCID userinfo %s', userinfo)

        namespaces = {
            'person': 'http://www.orcid.org/ns/person',
            'personal-details': 'http://www.orcid.org/ns/personal-details',
        }
        root = ElementTree.fromstring(userinfo.text)
        person = root.findall('.//person:person/person:name', namespaces)
        assert len(person) == 1
        person = person[0]

        omename = self._expand_template('name', token)
        # Not available in public API
        email = ''
        firstname = person.find(
            'personal-details:given-names', namespaces).text
        lastname = person.find('personal-details:family-name', namespaces).text

        return omename, email, firstname, lastname, None

    def userinfo_openid(self, token, userinfo_url):
        if self.get('openid.verify'):
            decoded = jwt_token_verify(
                token['id_token'], self.get('client.id'),
                self.get('openid.issuer'))
        else:
            decoded = jwt_token_noverify(token['id_token'])

        # Attempt to fill fields from token, if not possible then merge in
        # fields from userinfo
        try:
            omename, email, firstname, lastname = self._expand_all(decoded)
        except KeyError:
            userinfo = self.oauth.get(userinfo_url).json()
            logger.debug('Got openid userinfo %s', userinfo)
            userinfo.update(decoded)
            omename, email, firstname, lastname = self._expand_all(userinfo)
        return omename, email, firstname, lastname, None
