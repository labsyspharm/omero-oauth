#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from datetime import datetime

from django.conf import settings
from django.urls import reverse
from django.http import (
    HttpResponse,
    HttpResponseRedirect,
)
from django.template import loader as template_loader
from django.core.exceptions import PermissionDenied

import omero
from omero.rtypes import unwrap
from omeroweb.decorators import get_client_ip, parse_url
from omeroweb.webclient.decorators import (
    login_required,
    render_response,
)
from omeroweb.connector import Connector
from omero_version import (
    build_year,
    omero_version,
)

from omeroweb.webclient.webclient_gateway import OmeroWebGateway
from omeroweb.webclient.views import WebclientLoginView
from omeroweb.webadmin.webadmin_utils import upgradeCheck

from . import oauth_settings
from .providers import (
    OauthProvider,
    providers,
    OauthException)


logger = logging.getLogger(__name__)

USERAGENT = 'OMERO.oauth'


class OauthLoginView(WebclientLoginView):

    def handle_not_logged_in(self, request, error_message=None):
        auth_providers = providers()
        context = {
            'version': omero_version,
            'build_year': build_year,
            'auth_providers': auth_providers,
            'client_name': oauth_settings.OAUTH_DISPLAY_NAME,
            'url_suffix': '',
            'error_message': error_message
        }
        if hasattr(settings, 'LOGIN_LOGO'):
            context['LOGIN_LOGO'] = settings.LOGIN_LOGO

        t = template_loader.get_template('oauth/index.html')
        rsp = t.render(context, request=request)
        return HttpResponse(rsp)

    def post(self, request):
        oauth = None
        for (name, displayname) in providers():
            if request.POST.get(name):
                oauth = OauthProvider(name)
                break
        if not oauth:
            raise PermissionDenied('Invalid provider: {}'.format(name))

        authorization_url, state = oauth.authorization()
        # state: used for CSRF protection
        request.session['oauth_state'] = state
        logger.debug('OAuth provider: %s', name)
        return HttpResponseRedirect(authorization_url)


class OauthCallbackView(WebclientLoginView):

    def get(self, request, name):
        state = request.session.pop('oauth_state')
        if not state:
            raise PermissionDenied('OAuth state missing')
        code = request.GET.get('code')
        if not code:
            raise PermissionDenied('OAuth code missing')

        try:
            oauth = OauthProvider(name, state=state)
            token = oauth.token(code)
            logger.debug('Got OAuth token %s', token)

            userinfo = oauth.get_userinfo(token)
            logger.debug('Got userinfo %s', userinfo)

            uid, session = self.get_or_create_account_and_session(userinfo)
            return self.login_with_session(request, session)
        except OauthException as e:
            return error(request, error_message=e.message)

    def login_with_session(self, request, session):
        # Based on
        # https://github.com/ome/omero-web/blob/v5.22.1/omeroweb/webgateway/views.py#3421 (LoginView.post)
        username = session
        password = session
        server_id = 1
        is_secure = settings.SECURE
        connector = Connector(server_id, is_secure)

        compatible = True
        if settings.CHECK_VERSION:
            compatible = connector.check_version(USERAGENT)
        if compatible:
            conn = connector.create_connection(
                USERAGENT, username, password,
                userip=get_client_ip(request))
            if conn is not None:
                try:
                    connector.to_session(request)
                    # UpgradeCheck URL should be loaded from the server or
                    # loaded omero.web.upgrades.url allows to customize web
                    # only
                    try:
                        upgrades_url = settings.UPGRADES_URL
                    except AttributeError:
                        upgrades_url = conn.getUpgradesUrl()
                    upgradeCheck(url=upgrades_url)
                    # super.handle_logged_in does some connection preparation
                    # as wel as redirecting to the main page. We just want
                    # the preparation, so discard the response
                    self.handle_logged_in(request, conn, connector)
                    return HttpResponseRedirect(reverse('oauth_confirm'))
                finally:
                    conn.close(hard=False)

            raise Exception('Failed to login with session %s', session)
        raise Exception('Incompatible server')

    def post(self):
        # Disable super method
        raise PermissionDenied('POST not allowed')

    def get_or_create_account_and_session(self, userinfo):
        omename, email, firstname, lastname = userinfo
        adminc = create_admin_conn()
        try:
            e = adminc.getObject(
                'Experimenter', attributes={'omeName': omename})
            if e:
                uid = e.id
            else:
                gid = self.get_or_create_group(adminc)
                uid = self.create_user(
                    adminc, omename, email, firstname, lastname, gid)
            session = create_session_for_user(adminc, omename)
        finally:
            adminc.close()
        return uid, session

    def get_or_create_group(self, adminc, groupname=None):
        if not groupname:
            groupname = oauth_settings.OAUTH_GROUP_NAME
            if oauth_settings.OAUTH_GROUP_NAME_TEMPLATETIME:
                groupname = datetime.now().strftime(groupname)
        g = adminc.getObject(
            'ExperimenterGroup', attributes={'name': groupname})
        if g:
            gid = g.id
        else:
            logger.info('Creating new oauth group: %s %s', groupname,
                        oauth_settings.OAUTH_GROUP_PERMS)
            # Parent methods BlitzGateway.createGroup is easier to use than
            # the child method
            gid = super(OmeroWebGateway, adminc).createGroup(
                name=groupname, perms=oauth_settings.OAUTH_GROUP_PERMS)
        return gid

    def create_user(
            self, adminc, omename, email, firstname, lastname, groupid):
        logger.info('Creating new oauth user: %s group: %d', omename, groupid)
        uid = adminc.createExperimenter(
            omeName=omename, firstName=firstname, lastName=lastname,
            email=email, isAdmin=False, isActive=True,
            defaultGroupId=groupid, otherGroupIds=[],
            password=None)
        return uid


def create_admin_conn():
    adminc = OmeroWebGateway(
        host=oauth_settings.OAUTH_HOST,
        port=oauth_settings.OAUTH_PORT,
        username=oauth_settings.OAUTH_ADMIN_USERNAME,
        passwd=oauth_settings.OAUTH_ADMIN_PASSWORD,
        secure=True)
    if not adminc.connect():
        raise Exception('Unable to obtain admin connection')
    return adminc


def create_session_for_user(adminc, omename):
    # https://github.com/openmicroscopy/openmicroscopy/blob/v5.4.10/examples/OmeroClients/sudo.py
    ss = adminc.c.getSession().getSessionService()
    p = omero.sys.Principal()
    p.name = omename
    # p.group = 'user'
    p.eventType = 'User'
    # http://downloads.openmicroscopy.org/omero/5.4.10/api/slice2html/omero/api/ISession.html#createSessionWithTimeout
    # This is the absolute timeout (relative to creation time)
    user_session = unwrap(ss.createSessionWithTimeout(
        p, oauth_settings.OAUTH_USER_TIMEOUT * 1000).getUuid())
    logger.debug('Created new session: %s %s', omename, user_session)
    return user_session


@render_response()
def error(request, **kwargs):
    context = {
        'error_message': kwargs['error_message']
    }
    t = template_loader.get_template('oauth/error.html')
    rsp = t.render(context, request=request)
    return HttpResponse(rsp)

@login_required()
@render_response()
def confirm(request, conn=None, **kwargs):
    email = conn.getUser().getEmail()
    try:
        url = parse_url(settings.LOGIN_REDIRECT)
    except Exception:
        url = reverse("webindex")
    context = {
        'client_name': oauth_settings.OAUTH_DISPLAY_NAME,
        'username': conn.getUser().getName(),
        'email_missing': not email or not email.strip(),
        'sessiontoken_enabled': oauth_settings.OAUTH_SESSIONTOKEN_ENABLE,
        'url_suffix': '',
        'url': url,
    }
    t = template_loader.get_template('oauth/confirm.html')
    rsp = t.render(context, request=request)
    return HttpResponse(rsp)


@login_required()
@render_response()
def sessiontoken(request, conn=None, **kwargs):
    # createUserSession fails with a SecurityViolation
    # create session using sudo instead
    # ss = conn.c.getSession().getSessionService()
    # group = conn.getDefaultGroup(conn.getUser().id)
    # new_session = ss.createUserSession(
    #     oauth_settings.OAUTH_USER_TIMEOUT * 1000, 600 * 1000, group.name)

    context = {
        'client_name': oauth_settings.OAUTH_DISPLAY_NAME,
        'sessiontoken_enabled': oauth_settings.OAUTH_SESSIONTOKEN_ENABLE,
        'url_suffix': ''
    }
    if oauth_settings.OAUTH_SESSIONTOKEN_ENABLE:
        adminc = create_admin_conn()
        try:
            new_session = create_session_for_user(
                adminc, conn.getUser().omeName)
        finally:
            adminc.close()
        context['new_session'] = new_session
    t = template_loader.get_template('oauth/sessiontoken.html')
    rsp = t.render(context, request=request)
    return HttpResponse(rsp)
