#!/usr/local/bin/python
# $Id$

"""Legacy hack to evaluate which administrators have access permissions."""

import conf

class ZAuthError(Exception):
  pass

class ZAuth:
  def __init__(self, dbc):
    auth = {}
    self._dbc = dbc
  def check(self, zone, user):
    """Check that a given user has the rights to access a given zone.
    'DNSADMIN' and 'autoreg' have rights on every zone.
    """
    if user in ['DNSADMIN', 'autoreg']: return True
    zone = zone.upper()
    self._dbc.execute('SELECT EXISTS'
                      ' (SELECT 1 FROM admin_zone, zones, admins'
                      '  WHERE zones.id=admin_zone.zone_id'
                      '  AND admins.id=admin_zone.admin_id'
                      '  AND zones.name=%s'
                      '  AND admins.login=%s)', (zone, user))
    assert self._dbc.rowcount == 1
    found, = self._dbc.fetchone()
    return found
  def checkparent(self, domain, user):
    """Same as check(), after extracting the zone name from domain.
    """
    if '.' not in domain:
      return False
    zone = '.'.join(domain.split('.')[1:])
    return self.check(zone, user)
