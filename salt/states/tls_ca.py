# -*- coding: utf-8 -*-
'''
Manage Openssl TLS Certificate Authority
========================================

:codeauthor: :email:`Joe Julian <me@joejulian.name>`
:maturity: new
:platform: all

The tls_ca state can be used to create and manage OpenSSL Certificate
Authority states. The CA can be set as either absent or present.

.. versionadded:: 2015.5.1

.. code-block:: yaml
    mydomain.dom:
      tls_ca.present:
        - bits: 2048
        - days: 5478
        - CN: domain.dom
        - C: US
        - ST: Utah
        - L: Salt Lake City
        - O: SaltStack
        - OU: None
        - emailAddress: xyz@mydomain.dom
        - digest: sha256

    olddomain.dom:
      tls_ca.absent
'''
# Import python libs
from __future__ import absolute_import
import os
import re
import logging

# Import salt libs
import salt.utils
import salt.utils.locales

# Import 3rd-party libs
import salt.ext.six as six

log = logging.getLogger(__name__)

__virtualname__ = 'tls_ca'


def __virtual__():
    '''
    Only load if the tls module is available
    '''
    return __virtualname__ if 'tls.create_ca' in __salt__ else False


def _changes(ca_name,
             bits=2048,
             expires='',
             CN='localhost',
             C='US',
             ST='Utah',
             L='Salt Lake City',
             O='SaltStack',
             OU=None,
             emailAddress='xyz@pdq.net',
             fixmode=False,
             cacert_path=None,
             digest='sha256'):
    '''
    Return a dict of the changes required for a CA if the CA is present,
    otherwise return False
    '''
    change = {}

    # set days based on expires
    if expires is '':
        days = 5478
        expires = (
            datetime.date.today() + datetime.timedelta(5478)).isoformat()
    elif re.match('^([0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])$', expires):
        days = datetime.strptime(expires, '%Y-%m-%d')
    elif re.match('^([0-9]{4})-(1[0-2]|0[1-9])(3[01]|0[1-9]|[12][0-9])$', expires):
        days = datetime.strptime(expires, '%Y-%m%d')
    else:
        raise ValueError(
            'Failed parsing ISO 8601 date value: {0}'.format(expires))

    # check if CA exists in the correct state
    if not __salt__['tls.ca_exists'](ca_name, cacert_path=cacert_path):
        return False
    capath = __salt__['tls.get_ca'](ca_name, cacert_path=cacert_path)
    cainfo = __salt__['tls.cert_info'](capath)

    for attribute in ['CN', 'C', 'ST', 'L', 'OU', 'emailAddress']:
        # check if both sides are defined or undefined
        if bool(eval(attribute)) != (attribute in cainfo['subject'] and
                                     bool(cainfo['subject'][attribute])):
            change[attribute] = eval(attribute)
        # check that the attributes are the same
        elif (attribute in cainfo['subject'] and
                eval(attribute) != cainfo['subject'][attribute]):
            change[attribute] = eval(attribute)
    if datetime.datetime.utcfromtimestamp(cainfo['not_after']).date() != expires:
        change['expires'] = expires
    return change


def present(ca_name,
            bits=2048,
            expires='',
            CN='localhost',
            C='US',
            ST='Utah',
            L='Salt Lake City',
            O='SaltStack',
            OU=None,
            emailAddress='xyz@pdq.net',
            fixmode=False,
            cacert_path=None,
            digest='sha256'):
    '''
    Ensure that the root certificate is present with the specified properties

    ca_name
        name of the CA
    bits
        number of RSA key bits, Default is ``2048``
    expires 
        the expiration date of this certificate in ISO 8601 format,
        "2016-05-19".
        Default is 5478 days (15 years) from now
    CN
        common name in the request, Default is ``localhost``
    C
        country, Default is ``US``
    ST
        state, Default is ``Utah``
    L
        locality, Default is ``Salt Lake City``
    O
        organization, Default is ``SaltStack``
    OU
        organizational unit, Default is ``None``
    emailAddress
        email address for the CA owner, Default is ``xyz@pdq.net``
    cacert_path
        absolute path to ca certificates root directory
    digest
        The message digest algorithm. Must be a string describing a digest
        algorithm supported by OpenSSL (by EVP_get_digestbyname, specifically).
        For example, "md5" or "sha1". Default: 'sha256'
    '''
    comment = 'Root CA for {0} exists in the correct state'
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': comment.format(ca_name)
           }

    # set days based on expires
    if expires is '':
        days = 5478
        expires = (
            datetime.date.today() + datetime.timedelta(5478)).isoformat()
    elif re.match('^([0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])$', expires):
        days = datetime.strptime(expires, '%Y-%m-%d')
    elif re.match('^([0-9]{4})-(1[0-2]|0[1-9])(3[01]|0[1-9]|[12][0-9])$', expires):
        days = datetime.strptime(expires, '%Y-%m%d')
    else:
        ret['result'] = False
        ret['comment'] = 'Invalid expiration date: {0}'.format(expires)
        return ret

    # check if CA exists in the correct state
    changes = _changes(ca_name,
                       bits,
                       expires,
                       CN,
                       C,
                       ST,
                       L,
                       O,
                       OU,
                       emailAddress,
                       cacert_path,
                       digest)
    if changes:
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = ('The following user attributes are set to be '
                              'changed:\n')
            for key, val in changes.items():
                ret['comment'] += '{0}: {1}\n'.format(key, val)
            return ret
        # The certificate is present
        ret['changes'] = __salt__['tls.create_ca'](ca_name,
                                                   bits,
                                                   expires,
                                                   CN,
                                                   C,
                                                   ST,
                                                   L,
                                                   O,
                                                   OU,
                                                   emailAddress,
                                                   cacert_path,
                                                   digest,
                                                   replace=True)
        if ret['changes']:
            ret['comment'] = 'Replaced CA Certificate "{0}"'.format(
                ca_name)
        else:
            ret['comment'] = 'Failed to replace CA Certificate "{0}"'.format(
                ca_name)
            ret['result'] = False
            return ret
        changes = _changes(ca_name,
                           bits,
                           expires,
                           CN,
                           C,
                           ST,
                           L,
                           O,
                           OU,
                           emailAddress,
                           cacert_path,
                           digest)
        if changes:
            ret['comment'] = 'These values could not be changed: {0}'.format(
                changes)
            ret['result'] = False
        return ret
    if changes is False:
        # the certificate is not present, create it
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'CA certificate "{0}" set to be added.'.format(
                ca_name)
            return ret
        ret['changes'] = __salt__['tls.create_ca'](ca_name,
                                                   bits,
                                                   expires,
                                                   CN,
                                                   C,
                                                   ST,
                                                   L,
                                                   O,
                                                   OU,
                                                   emailAddress,
                                                   cacert_path,
                                                   digest)
        if ret['changes']:
            ret['comment'] = 'Created CA Certificate "{0}"'.format(
                ca_name)
        else:
            ret['comment'] = 'Failed to create CA Certificate "{0}"'.format(
                ca_name)
            ret['result'] = False
        return ret
