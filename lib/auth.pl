#!/usr/bin/perl
#
# $Id$
#
# Authorizations processing
#

# read the zone authorization file
sub zauth_read {
  local ($zname, $users);
  open(ZA, "$ZAUTFILE") || return;
  while (<ZA>) {
    next if /^#/;
    if (/^([^:]+):(.*)$/) {
      $zname = $1;
      $users = $2;
      $zname =~ tr/a-z/A-Z/;
      $ZAUTH{$zname} = $users;
    }
  }
  close ZA;
  return;
}

# check that a given user has the rights to access a given zone.
# DNSADMIN has rights on every zone.
sub zauth_check {
  local ($zone, $user) = @_;

  if ($user eq "DNSADMIN") { return "DNSADMIN"; }
  $zone =~ tr/a-z/A-Z/;
  foreach (split(/,/, $ZAUTH{$zone})) {
    return $_ if $_ eq $user;
  }
  return "";
}

1;
