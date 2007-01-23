#!/usr/bin/perl
#
# $Id$
#

# local configuration.
require "/usr/local/dns-manager/conf/config";
#require "$DNSLIB/md5.pl";
require "$DNSLIB/user.pl";
require "$DNSLIB/auth.pl";
require "$DNSLIB/cgi.pl";
require "$DNSLIB/val.pl";

&zauth_read;
  
$date=`date +%Y%m%d`; chop $date;

print "Content-Type: text/html\n\n<HTML><HEAD>";
print "</HEAD><BODY>\n";

&content;

if ($content{'rq'} && $content{'rq'} !~ /[a-zA-Z0-9-_]/) {
  print "Bad filename: $content{'rq'}\n";
  print "</BODY></HTML>\n";
  exit;
} elsif (!$ENV{'REMOTE_USER'}) {
  print "You need to authenticate to use this script.\n";
  print "</BODY></HTML>\n";
  exit;
} elsif (!chdir($VALDIR)) {
  print "Can't cd to $VALDIR: $!\n";
  print "</BODY></HTML>\n";
  exit;
}

$user = $ENV{'REMOTE_USER'};
$scriptname = $ENV{'SCRIPT_NAME'};

($user_pass, $user_mail, $user_mntby, $user_pmnt)
	= &user_get($user);

if (!$user_mail) {
  print "<STRONG>Cannot find user info for $user</STRONG><P>\n";
  print "</BODY></HTML>\n";
  exit;
}

if ($content{'action'} eq 'editwhois') {
  &doeditwhois($content{'rq'}, $user, $content{'whois'});
  &dodisplay($content{'rq'}, $user, $scriptname);
} elsif ($content{'action'} eq 'display') {
  &dodisplay($content{'rq'}, $user);
} elsif ($content{'action'} eq 'reject') {
  &doreject($content{'rq'}, $user, $date, $content{'reason'}, $content{'submit'});
} elsif ($content{'action'} eq 'info') {
  &doinfo($content{'rq'}, $user);
  &dostate($content{'rq'}, $user, "Answered");
} elsif ($content{'action'} eq 'setopen') {
  &dostate($content{'rq'}, $user, "Open");
  &dodisplay($content{'rq'}, $user);
} elsif ($content{'action'} eq 'setanswered') {
  &dostate($content{'rq'}, $user, "Answered");
} elsif ($content{'action'} eq 'accept') {
#  local ($err) = &md5_check("$user_pass:".&md5_get($content{'rq'}).
#			     ":$user:accept:$content{'rq'}",
#			     $content{'md5val'});
#  if (!$err) {
    &doaccept($content{'rq'}, $user, $date);
#  } else {
#    print "<STRONG>$err</STRONG></P>\n";
#    print "The MD5 you have provided is incorrect, or the file has been deleted.<P>\n";
#  }
} elsif ($content{'action'} eq 'delete') {
  local ($err) = &rq_remove($content{'rq'}, $user, $REJDIR);
  if ($err) {
    print "Unable to delete $content{'rq'}: $err<P>\n";
  } else {
    print "Deleted $content{'rq'}<P>\n";
  }
} else {
    &dodir($user, $scriptname);
}

print "</BODY></HTML>\n";
