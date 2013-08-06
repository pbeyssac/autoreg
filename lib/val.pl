#!/usr/bin/perl
#
# $Id$
#

# local configuration.
require "/usr/local/autoreg/conf/config";
#require "$DNSLIB/md5.pl";
require "$DNSLIB/misc.pl";
require "$DNSLIB/user.pl";
require "$DNSLIB/whois.pl";
require "$DNSLIB/requests.pl";

use FileHandle;
use IPC::Open2;

my $alldryrun = 0;
if ($alldryrun) { $WHOISHOST .= ':4343' }

sub tohtml {
    my $text = shift;
    $text =~ s/&/&amp;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/</&lt;/g;
    return $text;
}

sub dowhoisupdate {
    my $text = shift;
    my $dryrun = shift;
    my $opt = "-U";

    if ($dryrun) { $opt .= " -n" }

    my $pid = open2(*RD, *WR, "$WUPATH $opt 2>&1");
    print WR $text;
    close WR;

    my $st = "ERR";
    my $text = "";
    while (<RD>) {
	if (/^STATUS (\S+)$/) {
	    $st = $1;
	    last;
	}
	$text .= $_;
    }
    return ($st, $text);
}

sub mkwhoisform {
    local ($server, $request, $label) = ($_[0], $_[1], $_[2]);
    $server =~ s/ /+/g;
    $request =~ s/ /+/g;
    return "<A HREF=\"$WHOISCGI?server=$server&request=$request\">$label</A>\n";
}

sub dowhoisform {
    local ($server, $request, $label) = ($_[0], $_[1], $_[2]);
    print &mkwhoisform($server, $request, $label);
}

sub dolocalwhoisform {
    local ($request) = $_[0];
    print "Whois \"$request\" at ";
    &dowhoisform($WHOISHOST, $request, "EU.org");
    print "<BR>\n";
}

sub dowhoisforms {
    local ($request) = $_[0];
    print "Whois \"$request\" at ";
    &dowhoisform($WHOISHOST, $request, "EU.org");
    &dowhoisform("whois.ripe.net", $request, "RIPE");
    &dowhoisform("whois.internic.net", $request, "InterNIC");
    &dowhoisform("whois.aunic.net", $request, "AUNIC");
    &dowhoisform("whois.apnic.net", $request, "APNIC");
    print "<BR>\n";
}

sub dowhoisperson {
    my ($p) = $_[0];
    print "<H3>Current whois records for person $p</H3>\n";
    # -R: show real email rather than obfuscated one
    return &whois_html($WHOISHOST, "-R ".$p, 'person');
}

sub mkpages {
  my ($page) = $_[0];
  my ($npages) = $_[1];
  if ($page ne 0) { print "<a href=\"?page=".($page-1)."\">&lt;</a> "; }
  foreach $np (0..$npages-1) {
	if ($np ne $page) {
		print "<a href=\"?page=$np\">$np</a> ";
	} else {
		print "$np ";
	}
  }
  if ($page ne $npages-1) { print "<a href=\"?page=".($page+1)."\">&gt;</a> "; }
  print "<FORM ACTION=\"\" METHOD=\"GET\">\n";
  print "Domain: <INPUT NAME=\"dom\" TYPE=\"text\">\n";
  print "<INPUT TYPE=\"submit\" VALUE=\"Search\">\n";
  print "</FORM>\n";
}

sub dorqhtml {
  my ($rq, $replyto, $action, $domain, $lang, $state, $ndom,
	$args, $nemail) = @_;

  if ($action eq 'N') {
	$action = "New";
  } elsif ($action eq 'M') {
	$action = "Modify";
  } elsif ($action eq 'MZ') {
	$action = "Mod Zone";
  } elsif ($action eq 'MC') {
	$action = "Mod Contact";
  } elsif ($action eq 'D') {
	$action = "DEL";
  }

  my $wreplyto = &mkwhoisform("localhost", $replyto, $replyto);
  chop $wreplyto;
  my $tr = '<tr>';
  if ($action eq "DEL") {
    $tr = '<tr class="del">';
  } elsif ($ndom > 1 && $nemail > 1) {
    $tr = '<tr class="dup2">';
  } elsif ($ndom > 1) {
    $tr = '<tr class="dup">';
  } elsif ($domain =~ /\.[^\.]+\.[^\.]+\.[^\.]+/) {
    $tr = '<tr class="l3">';
  }
  if ($state eq 'Open') {
    $rqhtml = "$tr<td><A HREF=\"?$args\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto\n";
  } elsif ($state eq 'Answered' && $stateinfo) {
    $rqhtml = "$tr<td><A HREF=\"?$args\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto ($state by $stateinfo)\n";
  } else {
    $rqhtml = "$tr<td><A HREF=\"?$args\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto ($state)\n";
  }
  return $rqhtml;
}

sub dodom {
  my ($user, $scriptname, $domain) = ($_[0], $_[1], $_[2]);
  my @rqlist = &rq_list_dom($domain);
  my $ndom = @rqlist;

  print "<a href=\"?action=mdisplay&dom=$domain\">Show/Edit on one page</a>\n";
  print "<table>\n";
  my $dbh = &rq_get_db();
  foreach $rq (@rqlist) {
    my ($error, $replyto, $action, $domain, $lang, $state, $ndom,
	$dns, $dbrecords, $nemail)
	= &rq_db_get_info($dbh, $rq, $user);
    print &dorqhtml($rq, $replyto, $action, $domain, $lang, $state, $ndom,
	"rq=$rq", $nemail);
  }
  print "</table>\n";
}

sub dodir {
  local ($user) = $_[0];
  local ($scriptname) = $_[1];
  local ($page) = $_[2];
  local ($nbypage) = $_[3];
  my ($offset, $limit) = ($_[4], $_[5]);

  local ($foundone) = 0;

  local ($rq);

  if ($nbypage eq '') { $nbypage = 100 }

  my $num = &rq_num();
  my $npages = int(($num+$nbypage-1)/$nbypage);

  if ($page eq '') { $page = $npages-1 }

  my $offset = $page*$nbypage;
  my (@dirlist) = &rq_list($offset, $nbypage);

  print "\n";

  my $dbh = &rq_get_db();

  &mkpages($page, $npages);
  print "<table>\n";

  foreach $rq (@dirlist) {
    local ($error, $replyto, $action, $domain, $lang, $state, $ndom,
	$dns, $dbrecords, $nemail)
	= &rq_db_get_info($dbh, $rq, $user);

    if (!$error && $state ne 'WaitAck') {
      $foundone = 1;

      if ($ndom > 1 && $nemail > 1) {
        print &dorqhtml($rq, $replyto, $action, $domain, $lang, $state, $ndom,
		"dom=$domain", $nemail);
      } elsif ($ndom > 1) {
        print &dorqhtml($rq, $replyto, $action, $domain, $lang, $state, $ndom,
		"action=mdisplay&dom=$domain", $nemail);
      } else {
        print &dorqhtml($rq, $replyto, $action, $domain, $lang, $state, $ndom,
		"rq=$rq");
      }
    }
  }
  print "</table>\n";
  &mkpages($page, $npages);
  if (!$foundone) {
      print "Sorry, no request found...<BR>\n";
  }
}

sub dostate {
  local ($rq, $user, $newstate, $newstateinfo) = ($_[0], $_[1], $_[2], $_[3]);

  if ($alldryrun) {
    print "Void (test mode), end of processing.<P>\n";
    return "";
  }

  local ($error, $replyto, $action, $domain, $lang, $state)
	= &rq_set_state($rq, $user, $newstate, $newstateinfo);

  if ($error) {
    print "Error: $error.<P>\n";
  } else {
    print "State changed from $state to $newstate.<P>\n";
  }
}

sub doinfo {
  local ($rq) = $_[0];
  local ($user) = $_[1];

  if ($alldryrun) {
    print "Void (test mode), end of processing.<P>\n";
    return "";
  }

  local ($error, $replyto, $action, $domain, $lang, $state, $stateinfo,
	 $dns, $dbrecords)
	= &rq_get_info($rq, $user);
  if ($error) { print "Error: $error.<P>\n"; return; }

  $ENV{'ARLANG'} = $lang;
  do "$DNSCONF/msg-val";

  if (!open(SMU, "|$SENDMAIL -t")) {
    print "Unable to send mail.<P>\n";
    return;
  }

  printf SMU $VALHEADERS, $MSG_ADDR;
  printf SMU $MSG_SUBIN, $rq, $domain;
  print SMU "To: $replyto\n\n";
  printf SMU $MSG_BDYIN, $rq, $domain, $reason;
  print SMU $MSG_BYE;

  close(SMU);

  if ($? != 0) {
    print "<STRONG>sendmail returned an error !</STRONG><P>\n";
  }
}

sub doreject {
  local ($rq) = $_[0];
  local ($user) = $_[1];
  local ($date) = $_[2];
  local ($creason) = $_[3];
  local ($csubmit) = $_[4];

  if ($alldryrun) {
    print "Void (test mode), end of processing.<P>\n";
    return "";
  }

  local ($error, $replyto, $action, $domain, $lang, $state, $stateinfo,
	 $dns, $dbrecords)
	= &rq_get_info($rq, $user);
  if ($error) { print "Error: $error.<P>\n"; return; }

  $ENV{'ARLANG'} = $lang;
  do "$DNSCONF/msg-val";

  if (!open(SMU, "|$SENDMAIL -t")) {
    print "Unable to send mail.<P>\n";
    return;
  }

  my $reason;
  if ($creason) {
    $reason = $creason;
  } else {
    $reason = $csubmit;
  }

  printf SMU $VALHEADERS, $MSG_ADDR;
  printf SMU $MSG_SUBRJ, $rq, $domain;
  print SMU "To: $replyto\nBcc: $user_mail\n\n";
  printf SMU $MSG_BDYRJ, $rq, $domain, $reason;
  print  SMU $MSG_BYE;

  if ($action eq 'N' || $action eq 'M' || $action eq 'MC') {
    print SMU $MSG_BDYWR;
    foreach $line (split('\n', $dbrecords)) {
      if ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/) {
	  if ($1 eq "CHANGED") { $line = "changed: $user_mail $date"; }
	  elsif ($1 eq "MNT-BY") { $line = "mnt-by:  $user_mntby"; }
      }
      print SMU $line."\n";
    }
    print SMU "\n";
  }
  if ($action eq 'N' || $action eq 'M' || $action eq 'MZ') {
    print SMU $MSG_BDYZR;
    print SMU $dns;
    print SMU "\n";
  }

  close(SMU);
  if ($? != 0) {
    print "<STRONG>sendmail returned an error !</STRONG><P>\n";
    print "Request kept.\n";
  } else {
    &rq_remove($rq, $user, 'Rej');
    print "End of processing.<P>\n";
  }
}

sub doaccept {
  local ($rq) = $_[0];
  local ($user) = $_[1];
  local ($date) = $_[2];

  local ($line);

  local ($error, $replyto, $action, $domain, $lang, $state, $stateinfo,
	 $dns, $dbrecords)
	= &rq_get_info($rq, $user);
  if ($error) { print "Error: $error.<P>\n"; return; }

  $ENV{'ARLANG'} = $lang;
  do "$DNSCONF/msg-val";

  local ($pdom) = &parent_of($domain);
  local ($remadm) = &zauth_remote($pdom);
  if ($remadm) {
    print "[Zone $pdom handled by <A HREF=\"mailto:$remadm\">$remadm</A>]<P>\n";
  }

  #
  # Check request with respect to zone file
  #
  print "Checking DNS...<BR>\n";
  if (!open(AZ, "$AZPATH -c -a$action -u$user $domain 2>&1 |")) {
      print "<STRONG>Unable to test request in zone.</STRONG><P>\n";
      return "";
  } else {
    print "<PRE>\n";
    while (<AZ>) {
      s/&/&amp;/g;
      s/>/&gt;/g;
      s/</&lt;/g;
      print;
    }
    print "</PRE>\n";
    close (AZ);
    if ($? != 0) {
      print "<STRONG>This request cannot be executed.</STRONG>\n";
      # Ignore error if remote zone
      if (!$remadm) {
        return "";
      }
    }
  }

  my $output;
  if ($action ne 'MZ') {
    if ($action eq 'D') {
      ($error, $output) = &whois_domain($WHOISHOST, $domain);

      if ($error) {
        print "Unable to run whois: $error<P>\n";
        return;
      }
    } else {
      $output = $dbrecords;
    }
    my $t = "";
    foreach $line (split('\n', $output)) {
      if ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/ && $1 eq "domain"
	  && $action eq 'D') {
        $t .= "delete: $user_mail\n"
      }
      $t .= $line."\n";
    }
    $output = $t;
  }

  #
  # Check request with respect to whois database
  #
  my $text = "";
  foreach $line (split('\n', $output)) {
      if ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/) {
	if ($1 eq "CHANGED") {
	  $line = "changed: $user_mail";
	} elsif ($1 eq "MNT-BY") {
	  $line = "mnt-by:  $user_mntby";
	} elsif ($1 eq "mnt-by") {
	} elsif ($1 eq "domain") {
	  if ($action eq 'D') { $text .= "delete: $user_mail $date\n" }
	}
      }
      $text .= $line."\n";
  }
  print "Checking whois...<BR>\n";
  my ($st, $rtext) = &dowhoisupdate($text, 1);
  if ($st eq 'ERR') {
      my $htmltext = &tohtml($rtext);
      print "<STRONG>This request cannot be executed.</STRONG>\n";
      print "<PRE>\n$htmltext\n</PRE>\n";
      return "";
  }

  #
  # Prepare the mail for the user
  #
  if (!open(SMU, "|$SENDMAIL -t")) {
    print "Unable to send mail to user.<P>\n";
    return "";
  }

  printf SMU $VALHEADERS, $MSG_ADDR;
  printf SMU $MSG_SUBAC, $rq, $domain;
  if ($alldryrun) {
    print SMU "To: $user_mail\n\n";
  } else {
    print SMU "To: $replyto\nBcc: $user_mail\n\n";
  }
  printf SMU $MSG_BDYAC, $rq, $domain;

  my $err = 0;

  if ($action eq 'M' || $action eq 'MZ' || $action eq 'D') {
    print SMU $MSG_BDYZD;
    if (!open(AZ, "$AZPATH -a show -u$user $domain 2>&1 |")) {
      print SMU $MSG_NOREC;
      print "<STRONG>Unable to show existing records.</STRONG><P>\n";
    } else {
      while (<AZ>) { print SMU $_; }
      close(AZ);
      if ($?) {
	print SMU $MSG_NOREC;
	print "<STRONG>Unable to show existing records.</STRONG><P>\n";
      }
      print SMU "\n";
    }
  }
  if ($alldryrun) {
  } elsif ($action eq 'D') {
    if (!open(AZ, "$AZPATH -a delete -u$user $domain 2>&1 |")) {
      print "<STRONG>Unable to delete zone records.</STRONG><P>\n";
    } else {
      close(AZ);
      if ($? != 0) {
	print "<STRONG>Error when trying to delete zone records.</STRONG><P>\n";
	$err++;
      }
    }
  } elsif ($action eq 'N' || $action eq 'M' || $action eq 'MZ') {
    print SMU $MSG_BDYZI;
    if (!open(AZ, "| $AZPATH -a $action -u$user $domain")) {
      print SMU $MSG_NOINS;
      print "<STRONG>Unable to insert records.</STRONG><P>\n";
      $err++;
    } else {
      print AZ $dns;
      print SMU $dns;
      close (AZ);
      if ($? != 0) {
	print "<STRONG>Error when trying to insert records.</STRONG>\n";
	print SMU "Error when trying to insert records.\n";
	$err++;
      }
      print SMU "\n";
    }
  }

  ($st, $rtext) = &dowhoisupdate($text, $alldryrun);
  my $htmltext = &tohtml($rtext);
  if ($st ne 'OK') {
    print "<STRONG>Error when trying to handle whois records.</STRONG>\n";
    print SMU "Error when trying to handle whois records.\n";
    $err++;
  }
  print "Whois result:\n<PRE>\n$htmltext\n</PRE>\n";
  if (!$err) {
    print "The above has been <STRONG>committed</STRONG><BR>\n";
  } else {
    print "The above has been <STRONG>cancelled</STRONG><BR>\n";
  }

  if ($action eq 'N' || $action eq 'M' || $action eq 'MC') {
    print SMU $MSG_BDYWI;
    print SMU $rtext;
  }

  if ($remadm) {
    print SMU $MSG_OKRMB;
  } else {
    print SMU $MSG_OKBYE;
  }
  close(SMU);
  if ($? != 0) {
    print "<STRONG>sendmail returned an error !</STRONG><P>\n";
    print "Request kept.<P>\n";
    return;
  }

  # Prepare the mail for the remote zone administrator, if any

  if ($remadm) {
    if (!open(SMU, "|$SENDMAIL -t")) {
      print "Unable to send mail to remote administrator.<P>\n";
      return "";
    }
    print SMU "From: $user_mail\n";
    print SMU "To: $remadm\n";
    print SMU "Subject: request for $domain\n";
    print SMU "\n";

    if ($action =~ /^M/) {
      printf SMU $MSG_RQM, $domain;
    } elsif ($action =~ /^N/) {
      printf SMU $MSG_RQN, $domain;
    } elsif ($action =~ /^D/) {
      printf SMU $MSG_RQD, $domain;
    } 
    print SMU "\n";

    if ($action eq 'N' || $action eq 'M' || $action eq 'MZ') {
      print SMU $MSG_RQOKD;
      print SMU "\n";
      print SMU $dns;
      print SMU "\n";
    }

    if ($action eq 'N' || $action eq 'M' || $action eq 'MC') {
      print SMU $MSG_RQOKW;
      foreach $line (split('\n', $dbrecords)) {
        if ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/) {
	    if ($1 eq "CHANGED") { $line = "changed: $user_mail $date"; }
	    elsif ($1 eq "MNT-BY") { $line = "mnt-by:  $user_mntby"; }
        }
        print SMU $line."\n";
      }
      print SMU "\n";
    }
    close(SMU);
  }

  if (!$alldryrun && !$err) { &rq_remove($rq, $user, 'Acc'); }
  print "End of processing.<P>\n";
}

sub doeditwhois {
  local ($rq, $user, $newwhois) = ($_[0], $_[1], $_[2]);

  local ($line, $wh, $nempty);

  if ($alldryrun) {
    print "Void (test mode), end of processing.<P>\n";
    return "";
  }
  # Remove trailing \r
  # Remove trailing empty lines
  # Remove any content for mnt-by:
  # Remove changed:

  foreach $line (split('\n', $newwhois, $nl)) {
    if ($line =~ /\r$/) { chop $line }
    if ($line =~ /^mnt-by:/) {
        $line = "mnt-by: ";
    } elsif ($line =~ /^changed:/) {
	next;
    }
    $wh .= $line."\n";
    $nl++;
  }

  local ($error, $replyto, $action, $domain, $lang, $state)
	= &rq_set_whois($rq, $user, $wh);

  if ($error) { print "Error: $error.<P>\n"; return; }
}

sub mkwhoistext {
  my ($dbrecords) = @_;
  my ($line, $text, $htmltext, $nrows);
  $nrows=0;
  $dbrecords =~ s/\n$//sg;
  foreach $line (split('\n', $dbrecords)) {
    if ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/) {
	if ($1 eq "CHANGED") { next; }
	elsif ($1 eq "MNT-BY") { next; }
	elsif ($1 eq "source") { next; }
	elsif ($1 eq "nic-hdl" && $nh1) { $nh2 = $2; }
	elsif ($1 eq "nic-hdl") { $nh1 = $2; }
	elsif ($1 eq "tech-c") { $tc = $2; }
	elsif ($1 eq "admin-c") { $ac = $2; }
	elsif ($1 eq "person" && $pn1) { $pn2 = $2; }
	elsif ($1 eq "person") { $pn1 = $2; };
    }
    $text .= $line."\n";
    $nrows++;
  }
  return $text, $nrows
}

sub dodisplayeditwhois {
  my ($rq, $user, $scriptname) = @_;
  my ($error, $replyto, $action, $domain, $lang, $state, $stateinfo,
	$dns, $dbrecords)
	= &rq_get_info($rq, $user);
  if ($error) { print "Error: $error.<P>\n"; return; }

  my ($text, $nrows) = &mkwhoistext($dbrecords);

  $act="editwhois";
  print "Whois info domain $domain $rq\n";
  print "<div class=\"edwhois\">";
  print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
  print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
  print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
  print "<TEXTAREA NAME=\"whois\" COLS=70 ROWS=$nrows>\n";
  print "$text";
  print "</TEXTAREA><BR>\n";
  print "<INPUT TYPE=\"submit\" VALUE=\"Save\">\n";
  print "</FORM>\n";
  print "</div>\n";
}

sub dodisplay1 {
  my ($rq, $user, $scriptname, $suffix) = @_;
  my $dups = 0;

  local ($error, $replyto, $action, $domain, $lang, $state, $stateinfo,
	 $dns, $dbrecords)
	= &rq_get_info($rq, $user);

  print "<H2>Request $rq</H2>\n";

  if ($error) { print "Error: $error.<P>\n"; return; }

  $ENV{'ARLANG'} = $lang;
  do "$DNSCONF/msg-val";

  local ($pdom) = &parent_of($domain);
  local ($remadm) = &zauth_remote($pdom);
  if ($remadm) {
    print "[Zone $pdom handled by <A HREF=\"mailto:$remadm\">$remadm</A>]<P>\n";
  }

  if ($action eq 'N' || $action eq 'M' || $action eq 'MZ') {
    print "<H3>Records to be inserted in zone file</H3><PRE class=\"zone\">\n";
    print $dns;
    print "</PRE>\n";
  }

  if ($action eq 'N' || $action eq 'M' || $action eq 'MC') {
    $nh = "";
    print "<H3>Records to be inserted in WHOIS base</H3>\n";

    local ($htmltext);
    local ($text, $nrows) = &mkwhoistext($dbrecords);
    $htmltext = &tohtml($text);

    $act="dewhois";
    print "<PRE>\n";
    print "$text";
    print "</PRE>\n";
    print "<A HREF=\"$scriptname?rq=$rq&action=$act\" target=\"_blank\">Edit whois</a>\n";

    #
    # whois outputs for technical/admin contacts and person names
    #
    if ($tc && $tc ne $nh1 && $tc ne $nh2)
	{ $dups += (&dowhoisperson($tc) > 0); }
    if ($ac && $ac ne $tc && $ac ne $nh1 && $ac ne $nh2)
	{ $dups += (&dowhoisperson($ac) > 0); }
    if ($pn1 && $pn1 ne $tc && $pn1 ne $ac)
	{ $dups += (&dowhoisperson($pn1) > 0); }
    if ($pn2 && $pn2 ne $pn1 && $pn2 ne $tc && $pn2 ne $ac)
	{ $dups += (&dowhoisperson($pn2) > 0); }
  }

  if ($action eq 'MZ' || $action eq 'D' || $action eq 'M') {
    print "<HR><H3>Records to be deleted from zone file</H3><PRE>\n";
    if (!open(AZ, "$AZPATH -a show -u$user $domain 2>&1 |")) {
      print "Unable to show existing records.\n";
    } else {
      while (<AZ>) {
	s/&/&amp;/g;
	s/</&lt;/g;
	s/>/&gt;/g;
	print;
      }
      close(AZ);
    }
    print "</PRE>\n";
  }

  if ($action ne 'N') {
    print "<HR><H3>Current whois records for domain</H3>\n";
    &whois_html($WHOISHOST, $domain);
  }

  print "Requester: <a href=\"mailto:$replyto\">$replyto</a>\n";
  print "<INPUT NAME=\"rq$suffix\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
  print "<div>\n";
  print "Action: <select name=\"action$suffix\">\n";

  if ($state ne 'WaitAck') {
    print "<option value=\"none\">None</option>\n";
    print "<option value=\"accept\">Accept</option>\n";

    print "<option value=\"rejectdup\">Duplicate request</option>\n";
    print "<option value=\"rejectbog\">Reject: Bogus address</option>\n";
    print "<option value=\"rejectful\">Reject: no full name</option>\n";
    print "<option value=\"rejectnok\">Reject: already allocated</option>\n";

    print "<option value=\"rejectcust\">Reject (write reason below)</option>\n";
    print "<option value=\"setanswered\">Set state = Answered</option>\n";
  }
  print "<option value=\"delete\">Delete quietly</option>\n";

  print "</select>\n";
  print "</div>\n";
  if ($state ne 'WaitAck') {
    print "Reason:<div><TEXTAREA NAME=\"reason$suffix\" ROWS=3 COLS=77></TEXTAREA></div>\n";
  }
  print "<HR>\n";
}

sub dodisplaytail {
  my ($rq, $user, $scriptname) = @_;
  print "<INPUT TYPE=\"submit\" VALUE=\"Submit all\">\n";
  print "</FORM>\n";
  print "<HR><A HREF=\"$scriptname\">Return to directory</A>\n";
}

sub dodisplay {
  my ($rq, $user, $scriptname) = @_;
  print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
  &dodisplay1($rq, $user, $scriptname, 1);
  &dodisplaytail($rq, $user, $scriptname);
}

sub dodomdisplay {
  my ($user, $scriptname, $domain) = ($_[0], $_[1], $_[2]);
  my @rqlist = &rq_list_dom($domain);
  my $ndom = @rqlist;

  my $dbh = &rq_get_db();
  print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
  my $suffix = 1;
  foreach $rq (@rqlist) {
    my ($error, $replyto, $action, $domain, $lang, $state, $ndom,
	$dns, $dbrecords, $nemail)
	= &rq_db_get_info($dbh, $rq, $user);
    &dodisplay1($rq, $user, $scriptname, $suffix);
    $suffix++;
  }
  &dodisplaytail($rq, $user, $scriptname);
}

1;
