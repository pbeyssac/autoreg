#!/usr/bin/perl
#
# $Id$
#
# Helper function for CGI scripts
#

#
# This function stolen and adapted from webdns.pl.
# Originally written by Chris Lindblad <cjl@lcs.mit.edu>.
#
sub content { 
  local($buffer,@pairs,$key,$val);
  if ($ENV{'CONTENT_LENGTH'}) {
    if ($ENV{'CONTENT_TYPE'} ne 'application/x-www-form-urlencoded') {
      die('Unknown content type ',$ENV{'CONTENT_TYPE'},"\n");
    } 
    read(STDIN,$buffer,$ENV{'CONTENT_LENGTH'});
  } elsif ($ENV{'QUERY_STRING'}) { $buffer = $ENV{'QUERY_STRING'}; }
  else { $buffer = ''; }
  @pairs = split(/&/,$buffer);
  foreach $pair (@pairs) {
    ($key,$val) = split(/=/,$pair);
    $val =~ tr/+/ /;
    $val =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    if (defined($content{$key})) { $content{$key} .= ';'.$val; }
    else { $content{$key} = $val; }
  }
}

1;
