#!/usr/bin/perl
#
# $Id$
#

# local configuration.
require "/usr/local/autoreg/conf/config";
#require "$DNSLIB/md5.pl";
require "$DNSLIB/user.pl";
require "$DNSLIB/auth.pl";
require "$DNSLIB/cgi.pl";
require "$DNSLIB/val.pl";

&zauth_read;
  
$date=`date +%Y%m%d`; chop $date;

print "Content-Type: text/html; charset=utf-8\n\n";
print "<HTML><HEAD>";
print "<link rel=\"stylesheet\" type=\"text/css\" href=\"/adm/admstyle.css\">";
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
} elsif ($content{'action'} eq 'dewhois') {
  &dodisplayeditwhois($content{'rq'}, $user, $scriptname);
} elsif ($content{'action'} eq 'display') {
  &dodisplay($content{'rq'}, $user, $scriptname);
} elsif ($content{'action'} eq 'mdisplay' && $content{'dom'} ne '') {
  &dodomdisplay($user, $scriptname, $content{'dom'});
} elsif ($content{'dom'} ne '') {
  &dodom($user, $scriptname, $content{'dom'});
} elsif ($content{'action1'} ne '') {

  my $n = 1;

  while ($content{"action$n"} ne '') {
    my $act = $content{"action$n"};
    my $rq = $content{"rq$n"};
    my $reason = $content{"reason$n"};
    print "Processing $rq...<P>\n";
    if ($act eq 'rejectcust') {
      &doreject($rq, $user, $date, $reason, $reason);
    } elsif ($act eq 'rejectdup') {
      &doreject($rq, $user, $date, $reason, 'Duplicate request');
    } elsif ($act eq 'rejectbog') {
      &doreject($rq, $user, $date, $reason, 'Bogus address information');
    } elsif ($act eq 'rejectful') {
      &doreject($rq, $user, $date, $reason, 'Please provide a full name');
    } elsif ($act eq 'rejectnok') {
      &doreject($rq, $user, $date, $reason, 'Sorry, this domain is already allocated');
    } elsif ($act eq 'setanswered') {
      &doinfo($content{'rq'}, $user);
      &dostate($content{'rq'}, $user, "Answered");
    } elsif ($act eq 'setopen') {
      &dostate($rq, $user, "Open");
      &dodisplay($rq, $user, $scriptname);
    } elsif ($act eq 'setanswered') {
      &dostate($rq, $user, "Answered");
    } elsif ($act eq 'accept') {
      &doaccept($rq, $user, $date);
    } elsif ($act eq 'delete') {
      local ($err) = &rq_remove($rq, $user, 'DelQuiet');
      if ($err) {
        print "Unable to delete $rq: $err<P>\n";
      } else {
        print "Deleted $rq<P>\n";
      }
    } elsif ($act eq 'none') {
        print "Nothing done on $rq<P>\n";
    } else {
        print "What? On rq=$rq action=$action reason=$reason<P>\n";
    }
    $n++;
  }
} elsif ($content{'action'} eq '' && $content{'rq'} ne '') {
  &dodisplay($content{'rq'}, $user, $scriptname);
} else {
    &dodir($user, $scriptname, $content{'page'});
}

print "</BODY></HTML>\n";
