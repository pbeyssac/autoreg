#!/usr/bin/perl
#
# $Id$
#
# Primitives to control access to pending requests in $VALDIR.
#

# local configuration.
require "/usr/local/dns-manager/conf/config";
require "$DNSLIB/auth.pl";
require "$DNSLIB/misc.pl";

sub rq_set_state {
  local ($rq, $user, $newstate) = ($_[0], $_[1], $_[2]);
  local ($replyto, $action, $domain, $lang, $line, $state);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }

  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;
  ($action, $domain, $lang, $state) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  if (!open(NF, ">$VALDIR/$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }

  print NF "$replyto\n$action $domain $lang $newstate\n";
  while (<F>) {
    print NF $_;
  }
  close(F);
  close(NF);

  if (!rename("$VALDIR/$rq.new", "$VALDIR/$rq")) {
    return "Unable to update request file: $!";
    unlink("$VALDIR/$rq.new");
  } else {
    return ("", $replyto, $action, $domain, $lang, $state);
  }
}

sub rq_get_info {
  local ($rq, $user) = ($_[0], $_[1]);
  local ($replyto, $action, $domain, $lang, $line, $state, $dns, $dbrecords);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;

  ($action, $domain, $lang, $state) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  while (<F>) {
    last if ($_ eq ";;\n");
    $dns .= $_;
  }

  while (<F>) { if (/^$/) { $dbrecords.="CHANGED: \n\n"; next }
		elsif (/^mnt-by:/) { $dbrecords .="MNT-BY: \n"; next }
		elsif (/^;;$/) { last }
                $dbrecords .= $_; }

  close(F);

  return ("", $replyto, $action, $domain, $lang, $state, $dns, $dbrecords);
}

sub rq_remove {
  local ($rq, $user) = ($_[0], $_[1]);
  local ($replyto, $action, $domain, $lang, $line, $state, $dns, $dbrecords);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;
  ($action, $domain, $lang, $state) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }
  close(F);

  if (!unlink("$VALDIR/$rq")) {
    return "unlink: $!";
  }

  return;
}

sub rq_list {
  local (@rqlist);
   
  opendir(D, "$VALDIR") || die "Can't open $VALDIR: $!";
  local (@dirlist) = readdir(D);
  closedir(D);

  @dirlist = sort(@dirlist);

  for (@dirlist) {
     next if $_ =~ /^\./;
     @rqlist = (@rqlist, $_);
  }

  return @rqlist;
}

sub rq_create {
  local ($rq, $replyto, $action, $domain, $lang)
	= ($_[0], $_[1], $_[2], $_[3], $_[4]);
  local ($dns, $dbrecords);

  open(VR, ">$VALDIR/$rq") || die ("Cannot open $VALDIR/$rq: $!\n");
  print VR "$replyto\n";
  print VR "$req $domain $lang WaitAck\n";
  return "VR";
}

sub rq_end_dns {
  local ($rq, $fh) = ($_[0], $_[1]);
  print $fh ";;\n";
}

sub rq_end_create {
  local ($rq, $fh) = ($_[0], $_[1]);
  print $fh ";;\n";
  close($fh);
}

sub rq_make_id {
  local ($origin) = $_[0];
  local ($reqid);
  $reqid=`date +%Y%m%d%H%M%S`; chop $reqid;
  $reqid=$reqid."-$origin-$$";
  return $reqid;
}

sub rq_exists {
  local ($rq) = $_[0];
  if (!open(REQFILE, "$VALDIR/$rq")) { return; }
  close(REQFILE);
  return 1;
}

sub rq_extract {
  local ($rq) = $_[0];
  if ($rq =~
   /\[(\d\d\d\d\d\d\d\d\d\d\d\d\d\d-[a-zA-Z0-9]+-\d+)\]/) {
    $rq = $1;
    $rq =~ tr/A-Z/a-z/;
    return $rq;
  }
  return "";
}

1;
