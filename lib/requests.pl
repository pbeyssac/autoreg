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

# for flock()
$LOCK_SH = 1;
$LOCK_EX = 2;
$LOCK_UN = 8;

sub rq_set_whois {
  local ($rq, $user, $newwhois) = ($_[0], $_[1], $_[2]);
  local ($replyto, $action, $domain, $lang, $line, $state, $stateinfo);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  flock(F, $LOCK_EX);

  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;
  ($action, $domain, $lang, $state, $stateinfo) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  if (!open(NF, ">$VALDIR/.$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }
  flock(NF, $LOCK_EX);

  print NF "$replyto\n$line\n";

  # Copy zone info
  while (<F>) {
    print NF $_;
    if (/^;;$/) { last; };
  }
  # Skip old whois info
  while (<F>) {
    if (/^;;$/) { last; };
  }
  print NF $newwhois;
  print NF ";;\n";

  # Copy additional info
  while (<F>) {
    print NF;
  }

  # We need to keep the locks until after the rename.

  if (!rename("$VALDIR/.$rq.new", "$VALDIR/$rq")) {
    local ($err) = $!;
    unlink("$VALDIR/.$rq.new");
    close(F);
    close(NF);
    return "Unable to update request file: $err";
  } else {
    close(F);
    close(NF);
    return ("", $replyto, $action, $domain, $lang, $state, $stateinfo);
  }
}

sub rq_set_state {
  local ($rq, $user, $newstate, $newstateinfo) = ($_[0], $_[1], $_[2], $_[3]);
  local ($replyto, $action, $domain, $lang, $line, $state, $stateinfo);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  flock(F, $LOCK_EX);

  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;
  ($action, $domain, $lang, $state, $stateinfo) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  if (!open(NF, ">$VALDIR/.$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }
  flock(NF, $LOCK_EX);

  print NF "$replyto\n$action $domain $lang $newstate $newstateinfo\n";
  while (<F>) {
    print NF $_;
  }

  # We need to keep the locks until after the rename.

  if (!rename("$VALDIR/.$rq.new", "$VALDIR/$rq")) {
    local ($err) = $!;
    unlink("$VALDIR/.$rq.new");
    close(F);
    close(NF);
    return "Unable to update request file: $err";
  } else {
    close(F);
    close(NF);
    return ("", $replyto, $action, $domain, $lang, $state, $stateinfo);
  }
}

sub rq_get_info {
  local ($rq, $user) = ($_[0], $_[1]);
  local ($replyto, $action, $domain, $lang, $line, $state, $stateinfo,
	 $dns, $dbrecords);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  flock(F, $LOCK_SH);

  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;

  ($action, $domain, $lang, $state, $stateinfo) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  while (<F>) {
    last if ($_ eq ";;\n");
    $dns .= $_;
  }

  local ($in_obj);
  while (<F>) {
    if (/^;;$/) {
      if ($in_obj) { $dbrecords .= "CHANGED: \n\n"; }
      $in_obj = 0; last
    } elsif (/^$/) {
      if ($in_obj) { $dbrecords .= "CHANGED: \n\n"; }
      $in_obj = 0; next
    } elsif (/^mnt-by:/) {
      $dbrecords .= "MNT-BY: \n"; next
    }
    $dbrecords .= $_; $in_obj = 1;
  }
  if ($in_obj) { $dbrecords .= "CHANGED: \n\n"; }

  close(F);

  return ("", $replyto, $action, $domain, $lang, $state, $stateinfo,
	  $dns, $dbrecords);
}

sub rq_remove {
  local ($rq, $user) = ($_[0], $_[1]);
  local ($replyto, $action, $domain, $lang, $line, $state, $stateinfo,
	 $dns, $dbrecords);

  if (!open (F, "$VALDIR/$rq")) {
    return "Cannot find request $rq.";
  }
  flock(F, $LOCK_EX);
  $replyto = <F>; chop $replyto;
  $line = <F>; chop $line;
  ($action, $domain, $lang, $state, $stateinfo) = split(/ /, $line);

  if (!&zauth_check(&parent_of($domain), $user)) {
    close(F);
    return "Access to request $rq not authorized.";
  }

  # We need to keep the lock until after the unlink

  if (!unlink("$VALDIR/$rq")) {
    local ($err) = $!;
    close(F);
    return "unlink: $err";
  }
  close(F);

  return "";
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

  open(VR, ">$VALDIR/.$rq.tmp") || die "Cannot open $VALDIR/.$rq.tmp: $!\n";
  flock(VR, $LOCK_EX);
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
  rename("$VALDIR/.$rq.tmp", "$VALDIR/$rq")
	|| die "Cannot rename $VALDIR/.$rq.tmp: $!\n";
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
