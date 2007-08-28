#!/usr/bin/perl
#
# $Id$
#
# Access users file.

# local configuration.
require "/usr/local/autoreg/conf/config";

sub user_get {
  local ($remuser) = $_[0];

  if (!open(UP, $PASSFILE)) {
	return "";
  }
  while (<UP>) {
	next if /^#/;
	chop;
	local ($user, $pass, $email, $mntby, $passmnt) = split(/:/);
	if ($user eq $remuser) {
	  close UP;
	  return ($pass, $email, $mntby, $passmnt); }
  }
  close (UP);
  return "";
}

1;
