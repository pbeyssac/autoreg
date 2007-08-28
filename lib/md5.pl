#!/usr/bin/perl
#
# $Id$
#

# local configuration.
require "/usr/local/autoreg/conf/config";

#
# Compute MD5 on a given file
#
sub md5_get {
  local ($file) = $_[0];
  local ($mymd5);
  if (!open(MD5, "$MD5PATH < $file |")) {
    return "";
  } else {
    if (!($mymd5 = <MD5>)) {
      close(MD5);
      return "";
    } else {
      chop $mymd5;
      close(MD5);
      return $mymd5;
    }
  }
}

#
# Compute MD5 of the given string.
# Return MD5 if ok, else return nothing.
#
sub md5_compute {
  local ($string) = @_;

  if ($string !~ /^[a-zA-Z0-9\-\/;!:]+$/) {
	return "";
  }

  if (!open(MD5, "(echo \'$string\') | $MD5PATH |")) {
    return "";
  } else {
    if (!($mymd5 = <MD5>)) {
      close(MD5);
      return "";
    } else {
      chop $mymd5;
    }
  }
  close(MD5);
  return $mymd5;
}

#
# Check MD5 of the given string against the MD5 we received.
# Return 0 if ok, else 1 or error string.
#
sub md5_check {
  local ($string, $gotmd5) = @_;
  return &md5_compute($string) ne $gotmd5;
}

1;
