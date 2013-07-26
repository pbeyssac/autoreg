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
}

sub dodir {
  local ($user) = $_[0];
  local ($scriptname) = $_[1];
  local ($page) = $_[2];
  local ($nbypage) = $_[3];
  local (@dirlist) = &rq_list();
  local (@domlist);
  local (@rqlist);
  local (@duprq);
  local (@l3rq);
  local ($foundone) = 0;

  local ($rq);
  local ($rqhtml);

  if ($page eq '') { $page = 0 }
  if ($nbypage eq '') { $nbypage = 100 }
  print "\n";

  my $dbh = &rq_get_db();

  my $n = 1;
  foreach $rq (@dirlist) {
    local ($error, $replyto, $action, $domain, $lang, $state, $stateinfo)
	= &rq_db_get_info($dbh, $rq, $user);

    if (!$error && $state ne 'WaitAck') {
      $foundone = 1;

      if ($action eq 'N') {
	$action = "New       ";
      } elsif ($action eq 'M') {
	$action = "Modify    ";
      } elsif ($action eq 'MZ') {
	$action = "Mod Zone  ";
      } elsif ($action eq 'MC') {
	$action = "Mod Contact";
      } elsif ($action eq 'D') {
	$action = "DEL";
      }
      my $wreplyto = &mkwhoisform("localhost", $replyto, $replyto);
      if ($state eq 'Open') {
	$rqhtml = "<tr><td>$n<td><A HREF=\"$scriptname?action=display\&rq=$rq\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto\n";
      } elsif ($state eq 'Answered' && $stateinfo) {
	$rqhtml = "<tr><td>$n<td><A HREF=\"$scriptname?action=display\&rq=$rq\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto ($state by $stateinfo)\n";
      } else {
	$rqhtml = "<tr><td>$n<td><A HREF=\"$scriptname?action=display\&rq=$rq\" target=\"_blank\"><TT>$rq</TT></A><td>$action<td>$lang<td>$domain<td>$wreplyto ($state)\n";
      }
      $n++;
      if ($domlist{$domain}) {
	$rqlist{$domlist{$domain}} = $rqlist{$domlist{$domain}} . $rqhtml;
	$duprq{$domlist{$domain}} = 1;
      } else {
	if ($domain =~ /\.[^\.]+\.[^\.]+\.[^\.]+/) {
		$l3rq{$rq} = 1;
	}
	$domlist{$domain} = $rq;
	$rqlist{$rq} = $rqhtml;
      }
    }
  }
  my @rqs = sort(keys %rqlist);
  my $num = @rqs;
  my $startat = $page*$nbypage;

  my $npages = int(($num+$nbypage-1)/$nbypage);
  &mkpages($page, $npages);
  print "<table>\n";
  foreach $key (@rqs[$startat..$startat+$nbypage-1]) {
	my $rql = $rqlist{$key};
	if ($duprq{$key}) {
		$rql =~ s/<tr>/<tr style="background-color:#fcc">/g;
	} elsif ($l3rq{$key}) {
		$rql =~ s/<tr>/<tr style="background-color:#cfc">/g;
	}
	print $rql;
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
  if (defined($creason)) {
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
    &rq_remove($rq, $user, $REJDIR);
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

  if (!$alldryrun && !$err) { &rq_remove($rq, $user, $ACCDIR); }
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
  # Remove empty lines (some browsers suppress them when POSTing)
  # Remove leading "_" lines
  # Replace other "_" with empty lines
  # Remove trailing empty lines
  # Remove any content for mnt-by:
  # Remove changed:
  # Force an empty line before "person:" and "domain:"

  foreach $line (split('\n', $newwhois, $nl)) {
    if ($line =~ /\r$/) { chop $line }
    if ($line =~ /^$/) {
        next;
    } elsif ($line =~ /^_$/) {
        $nempty++;
        next;
    } elsif ($line =~ /^person:/) {
        $nempty = 1;
    } elsif ($line =~ /^domain:/) {
        $nempty = 1;
    } elsif ($line =~ /^mnt-by:/) {
        $line = "mnt-by: ";
    } elsif ($line =~ /^changed:/) {
	next;
    }
    if ($nempty) {
      if ($nl) { $wh .= "\n" }
      $nempty = 0;
    }
    $wh .= $line."\n";
    $nl++;
  }

  local ($error, $replyto, $action, $domain, $lang, $state)
	= &rq_set_whois($rq, $user, $wh);

  if ($error) { print "Error: $error.<P>\n"; return; }
}

sub dodisplay {
  local ($rq) = $_[0];
  local ($user) = $_[1];
  local ($scriptname) = $_[2];
  my $dups = 0;

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

  if ($action eq 'N' || $action eq 'M' || $action eq 'MZ') {
    print "<H3>Records to be inserted in zone file</H3><PRE style=\"background-color:#eee\">\n";
    print $dns;
    print "</PRE>\n";
  }

  if ($action eq 'N' || $action eq 'M' || $action eq 'MC') {
    $nh = "";
    print "<H3>Records to be inserted in WHOIS base</H3>\n";

    print "(lines with a \"_\" by itself are considered empty)<BR>\n";

    local ($line, $text, $htmltext, $nrows);
    $nrows=3;

    foreach $line (split('\n', $dbrecords)) {
      if ($line =~ /^\s*$/) {
	  $text .= $line."\n";
          $line = "_";
	  $htmltext .= "_\n";
      } elsif ($line =~ /^([a-zA-Z0-9-]*):\s*(.*)$/) {
	  if ($1 eq "CHANGED") { $line = "changed: $user_mail"; }
	  elsif ($1 eq "MNT-BY") { $line = "mnt-by:  $user_mntby"; }
	  elsif ($1 eq "nic-hdl" && $nh1) { $nh2 = $2; }
	  elsif ($1 eq "nic-hdl") { $nh1 = $2; }
	  elsif ($1 eq "tech-c") { $tc = $2; }
	  elsif ($1 eq "admin-c") { $ac = $2; }
	  elsif ($1 eq "person" && $pn1) { $pn2 = $2; }
	  elsif ($1 eq "person") { $pn1 = $2; };
	  $text .= $line."\n";
	  $htmltext .= $line."\n";
      }
      $nrows++;
    }
    $htmltext = &tohtml($htmltext);

    $act="editwhois";
    print "<div style=\"float:left\">";
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "<TEXTAREA NAME=\"whois\" COLS=70 ROWS=$nrows>\n";
    print "$text";
    print "_\n_\n_\n</TEXTAREA><BR>\n";
    print "If necessary, edit the above then\n";
    print "<INPUT TYPE=\"submit\" VALUE=\"submit\"> to save changes\n";
    print "</FORM>\n";
    print "</div>\n";

    print "<div style=\"background-color:#eee\"><STRONG>Uncommitted</STRONG> dry-run results:\n";
    my ($st, $rtext) = &dowhoisupdate($text, 1);
    if ($st ne 'OK') {
	print "<STRONG>Error</STRONG>\n";
    }
    my $htmltext = &tohtml($rtext);
    print "<PRE>\n$htmltext</PRE></div>\n";

    #
    # Local form only for whois on domain name
    #
    print "<div style=\"clear:both\">\n";
    &dolocalwhoisform($domain);
    print "</div>\n";
    #
    # Forms for whois on NIC handles
    #
    if ($nh1) { &dowhoisforms($nh1); }
    if ($nh2 && $nh1 ne $nh2) { &dowhoisforms($nh2); }
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
    #
    # Forms for whois on technical/admin contacts and person names
    #
    if ($tc && $tc ne $nh1 && $tc ne $nh2)
	{ &dowhoisforms($tc); }
    if ($ac && $ac ne $tc && $ac ne $nh1 && $ac ne $nh2)
	{ &dowhoisforms($ac); }
    if ($pn1 && $pn1 ne $tc && $pn1 ne $ac)
	{ &dolocalwhoisform($pn1); }
    if ($pn2 && $pn2 ne $pn1 && $pn2 ne $tc && $pn2 ne $ac)
	{ &dolocalwhoisform($pn2); }
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

#  $mymd5 = &md5_get($rq);
#
#  if (!$mymd5) {
#    print "<STRONG>Unable to compute MD5 for \"$rq\"</STRONG><P>\n";
#  }

  print "<HR>\n";

  if ($state ne 'WaitAck') {
    $act='accept';
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
#    print ":$mymd5:$user:$act:$rq<BR>\n";
#    print "<INPUT NAME=\"md5val\" SIZE=34> MD5<BR>\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "<INPUT TYPE=\"submit\" VALUE=\"Accept and mail to $replyto\">\n";
    print "</FORM>\n";

    $act='reject';
    print "Pre-filled answers:\n";
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
    print "<INPUT TYPE=\"submit\" NAME=\"submit\" VALUE=\"Duplicate request\">\n";
    print "<INPUT TYPE=\"submit\" NAME=\"submit\" VALUE=\"Bogus address information\">\n";
    print "<INPUT TYPE=\"submit\" NAME=\"submit\" VALUE=\"Please provide a full name\">\n";
    print "<INPUT TYPE=\"submit\" NAME=\"submit\" VALUE=\"Sorry, this domain is already allocated\">\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "</FORM>\n";

    $act='reject';
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
    print "<INPUT TYPE=\"submit\" VALUE=\"Reject and mail to $replyto\"><BR>\n";
    print "Reason:<BR><TEXTAREA NAME=\"reason\" ROWS=6 COLS=77></TEXTAREA>\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "</FORM>\n";

    $act='setanswered';
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "<INPUT TYPE=\"submit\" VALUE=\"Set state = Answered\"><BR>\n";
    print "(to mark the request as waiting for more details from the requester)<BR>\n";
    print "</FORM>\n";

  } else {
    print "(request not yet confirmed by user)<P>\n";
    $act='setopen';
    print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
    print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
    print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
    print "<INPUT TYPE=\"submit\" VALUE=\"Set state = Open\"><BR>\n";
    print "(to consider the request as acknowledged by the user)<BR>\n";
    print "</FORM>\n";
  }

#  $act='info';
#  print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
#  print "<INPUT TYPE=\"submit\" VALUE=\"Ask more info to $replyto\"><BR>\n";
#  print "Reason:<TEXTAREA NAME=\"reason\" ROWS=10 COLS=77></TEXTAREA>\n";
#  print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
#  print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
#  print "</FORM>\n";

  $act='delete';
  print "<FORM ACTION=\"$scriptname\" METHOD=\"POST\">\n";
  print "<INPUT NAME=\"action\" TYPE=\"hidden\" VALUE=\"$act\">\n";
  print "<INPUT NAME=\"rq\" TYPE=\"hidden\" VALUE=\"$rq\">\n";
  print "<INPUT TYPE=\"submit\" VALUE=\"Delete quietly\">\n";
  print "</FORM>\n";

  print "<HR><A HREF=\"$scriptname\">Return to directory</A>\n";
}

1;
