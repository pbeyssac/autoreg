#!/usr/bin/perl
#
# $Id$
#
# Authorizations processing
#

# read the zone authorization file
sub zauth_read {
  local ($zname, $users, $email);
  open(ZA, "$ZAUTFILE") || return;
  while (<ZA>) {
    next if /^#/;
    ($zname, $users, $email) = split(/[:\n]/, $_);
    $zname =~ tr/a-z/A-Z/;
    $ZAUTH{$zname} = $users;
    $ZAUTHADDR{$zname} = $email;
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

# Returns the e-mail address of the maintainer if the zone is remote
sub zauth_remote {
  local ($zone) = $_[0];
  return $ZAUTHADDR{$zone};
}

1;
