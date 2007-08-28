#!/usr/bin/perl
#
# $Id$
#
# Primitives to control access to pending requests in $VALDIR.
#

# local configuration.
require "/usr/local/autoreg/conf/config";
require "$DNSLIB/auth.pl";
require "$DNSLIB/misc.pl";

# for flock()
$LOCK_SH = 1;
$LOCK_EX = 2;
$LOCK_UN = 8;

#
# Update whois info in request
#
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

  umask 022;
  if (!open(NF, ">$VALDIR/.$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }
  flock(NF, $LOCK_EX);

  print NF "$replyto\n$line\n";
  # add zone tag, if not yet converted
  if ($_ = <F>) {
     if (!/^;;zone/) { print NF ";;zone\n"; print NF $_; }
     else { print NF $_; }
  }
  # Copy zone info
  while (<F>) {
    if (/^;;/) { last; };
    print NF $_;
  }
  # Skip old whois info
  while (<F>) {
    if (/^;;/) { last; };
  }
  print NF ";;whois\n";
  print NF $newwhois;
  print NF ";;attr\n";

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

#
# Update attribute in request
#
sub rq_set_attr {
  local ($rq, $user, $newattr, $newval) = ($_[0], $_[1], $_[2], $_[3]);
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

  umask 022;
  if (!open(NF, ">$VALDIR/.$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }
  flock(NF, $LOCK_EX);

  print NF "$replyto\n$line\n";
  # add zone tag, if not yet converted
  if ($_ = <F>) {
     if (!/^;;zone/) { print NF ";;zone\n"; print NF $_; }
     else { print NF $_; }
  }

  # Copy zone info
  while (<F>) {
    if (/^;;/) { last; };
    print NF $_;
  }
  # force whois tag
  print NF ";;whois\n";
  # Copy old whois info
  while (<F>) {
    if (/^;;/) { last; };
    print NF $_;
  }

  if (/^;;attr/) {
    # attr section found, update the attribute we're looking for
    local ($found) = 0;
    print NF $_;
    while (<F>) {
      if (/^;;/) { last }
      if (!$found && /^$newattr:/) {
	print NF "$newattr: $newval\n";
        $found = 1;
      } else {
	print NF $_;
      }
    }
    if (!$found) {
      print NF "$newattr: $newval\n";
    }
    print NF $_;
  } elsif (/^;;$/) {
    # no attr section, old format:
    # convert format, insert attr section
    print NF ";;attr\n";
    print NF "$newattr: $newval\n";
    # force additional info tag
    print NF ";;add\n";
  } else {
    # no attr section, new format: insert attr section
    local ($savetag) = $_;
    # no attribute yet
    print NF ";;attr\n";
    print NF "$newattr: $newval\n";
    print NF "$savetag";
  }

  # Copy additional info
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

#
# Update state
#
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

  umask 022;
  if (!open(NF, ">$VALDIR/.$rq.new")) {
    close(F);
    return "Unable to update request file.";
  }
  flock(NF, $LOCK_EX);

  print NF "$replyto\n$action $domain $lang $newstate $newstateinfo\n";
  # add zone tag, if not yet converted
  if ($_ = <F>) {
     if (!/^;;zone/) { print NF ";;zone\n"; print NF $_; }
     else { print NF $_; }
  }
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

#
# Return request info
#
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

  if ($_ = <F>) {
    if (!/^;;zone/) { $dns = $_; }
  }

  # Read zone info
  while (<F>) {
    last if (/^;;/);
    $dns .= $_;
  }

  # Read whois info
  local ($in_obj);
  while (<F>) {
    if (/^;;/) {
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

#
# Delete request
#
sub rq_remove {
  local ($rq, $user, $moveto) = ($_[0], $_[1], $_[2]);
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

  # We need to keep the lock until after the rename

  if (!rename("$VALDIR/$rq", "$moveto/$rq")) {
    local ($err) = $!;
    close(F);
    return "rename: $err";
  }
  close(F);

  return "";
}

#
# Return list of current requests
#
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

#
# Create a new request
#
sub rq_create {
  local ($rq, $replyto, $action, $domain, $lang)
	= ($_[0], $_[1], $_[2], $_[3], $_[4]);
  local ($dns, $dbrecords);

  umask 022;
  open(VR, ">$VALDIR/.$rq.tmp") || die "Cannot open $VALDIR/.$rq.tmp: $!\n";
  flock(VR, $LOCK_EX);
  print VR "$replyto\n";
  print VR "$req $domain $lang WaitAck\n;;zone\n";
  return "VR";
}

sub rq_end_dns {
  local ($rq, $fh) = ($_[0], $_[1]);
  print $fh ";;whois\n";
}

sub rq_end_create {
  local ($rq, $fh) = ($_[0], $_[1]);
  print $fh ";;add\n";
  rename("$VALDIR/.$rq.tmp", "$VALDIR/$rq")
	|| die "Cannot rename $VALDIR/.$rq.tmp: $!\n";
  close($fh);
}

#
# Generate a request id
#
sub rq_make_id {
  local ($origin) = $_[0];
  local ($reqid);
  $reqid=`date +%Y%m%d%H%M%S`; chop $reqid;
  $reqid=$reqid."-$origin-$$";
  return $reqid;
}

#
# Check given request exists
#
sub rq_exists {
  local ($rq) = $_[0];
  if (!open(REQFILE, "$VALDIR/$rq")) { return ""; }
  close(REQFILE);
  return 1;
}

#
# Extract a request id from a string
#
sub rq_extract {
  local ($rq) = $_[0];
  if ($rq =~
   /(\d\d\d\d\d\d\d\d\d\d\d\d\d\d-[a-zA-Z0-9]+-\d+)/) {
    $rq = $1;
    $rq =~ tr/A-Z/a-z/;
    return $rq;
  }
  return "";
}

1;
