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
        - expires: "2030-05-21"
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


def _changes(name,
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
    if not __salt__['tls.ca_exists'](name, cacert_path=cacert_path):
        return False
    capath = __salt__['tls.get_ca'](name, cacert_path=cacert_path)
    cainfo = __salt__['tls.cert_info'](capath)

    for attribute in ['CN', 'C', 'ST', 'L', 'OU', 'emailAddress']:
        # check if both sides are defined or undefined
        if bool(locals()[attribute]) != (attribute in cainfo['subject'] and
                                     bool(cainfo['subject'][attribute])):
            change[attribute] = locals()[attribute]
        # check that the attributes are the same
        elif (attribute in cainfo['subject'] and
                locals()[attribute] != cainfo['subject'][attribute]):
            change[attribute] = locals()[attribute]
    if datetime.datetime.utcfromtimestamp(cainfo['not_after']).date() != expires:
        change['expires'] = expires
    return change


def present(name,
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

    name
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
           'comment': comment.format(name)
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
    changes = _changes(name,
                       bits=bits,
                       expires=expires,
                       CN=CN,
                       C=C,
                       ST=ST,
                       L=L,
                       O=O,
                       OU=OU,
                       emailAddress=emailAddress,
                       cacert_path=cacert_path,
                       digest=digest)
    if changes:
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = ('The following user attributes are set to be '
                              'changed:\n')
            for key, val in changes.items():
                ret['comment'] += '{0}: {1}\n'.format(key, val)
            return ret
        # The certificate is present
        ret['changes'] = __salt__['tls.create_ca'](name,
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
                name)
        else:
            ret['comment'] = 'Failed to replace CA Certificate "{0}"'.format(
                name)
            ret['result'] = False
            return ret
        changes = _changes(name,
                           bits=bits,
                           expires=expires,
                           CN=CN,
                           C=C,
                           ST=ST,
                           L=L,
                           O=O,
                           OU=OU,
                           emailAddress=emailAddress,
                           cacert_path=cacert_path,
                           digest=digest)
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
                name)
            return ret
        ret['changes'] = __salt__['tls.create_ca'](name,
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
                name)
        else:
            ret['comment'] = 'Failed to create CA Certificate "{0}"'.format(
                name)
            ret['result'] = False
        return ret


def absent(name, cacert_path=None):
    '''
    Ensure that the named CA is absent from the specified path

    name
        name of the CA
    cacert_path
        absolute path to ca certificates root directory
    '''
    ret = {'name': name,
           'changes': {},
           'result': True,
           'comment': ''}

    # if the certificate exists, make it not exist
    if __salt__['tls.ca_exists'](name, cacert_path=cacert_path):
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'CA Certificate "{0}" set for removal'.format(
                name)
            return ret
        capath = __salt__['tls.get_ca'](name, cacert_path=cacert_path)
        os.remove(capath)
        ret['comment'] = 'Removed CA Certificate "{0}"'.format(name)
        # also remove the private key
        os.remove("{0}key".format(capath[:-3]))
        ret['comment'] += ' Removed CA private key "{0}"'.format(name)
        ret['changes'][name] = 'removed'
    else:
        ret['comment'] = 'CA Certificate "{0}" is not present.'.format(name)
    return ret
