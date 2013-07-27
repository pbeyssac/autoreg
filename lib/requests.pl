#!/usr/bin/perl
#
# $Id$
#
# Primitives to control access to pending requests
#

# local configuration.
require "/usr/local/autoreg/conf/config";
require "$DNSLIB/auth.pl";
require "$DNSLIB/misc.pl";

use DBI;

my $dbparam = "dbi:PgPP:dbname=eu.org";
my $dbuser = "autoreg";

sub rq_get_db {
  return $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
}

sub rq_db_get_domain {
  my ($dbh, $rq) = ($_[0], $_[1]);
  my $sth = $dbh->prepare("SELECT fqdn FROM requests WHERE id=?");
  $sth->execute($rq);
  my @row = $sth->fetchrow_array;
  return @row[0];
}

#
# Update whois info in request
#
sub rq_set_whois {
  local ($rq, $user, $newwhois) = ($_[0], $_[1], $_[2]);

  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  if (!&zauth_check(&parent_of(&rq_db_get_domain($dbh, $rq)), $user)) {
    return "Access to request $rq in domain $domain not authorized.";
  }

  $sth = $dbh->prepare("UPDATE requests SET whoisrecord=? WHERE id=?");
  $sth->execute($newwhois, $rq);

  if ($sth->rows ne 1) {
    return "UPDATE didn't find request $rq";
  } else {
    return "";
  }
}

#
# Update state
#
sub rq_set_state {
  local ($rq, $user, $newstate, $newstateinfo) = ($_[0], $_[1], $_[2], $_[3]);
  local ($replyto, $action, $domain, $lang, $line, $state, $stateinfo);

  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});

  if (!&zauth_check(&parent_of(&rq_db_get_domain($dbh, $rq)), $user)) {
    return "Access to request $rq not authorized.";
  }

  my $sth = $dbh->prepare("UPDATE requests SET state=? WHERE id=?");
  $sth->execute($newstate, $rq);

  if ($sth->rows ne 1) {
    return "UPDATE didn't find request $rq";
  } else {
    return "";
  }
}

#
# Return request info
#
sub rq_db_get_info {
  local ($dbh, $rq, $user) = ($_[0], $_[1], $_[2]);

  my $sth = $dbh->prepare("SELECT email, action, fqdn, language, state,
	zonerecord, whoisrecord FROM requests WHERE id=?");
  $sth->execute($rq);

  my @row = $sth->fetchrow_array;
  my ($replyto, $action, $domain, $lang, $state, $dns, $dbrecords) = @row;

  if (!&zauth_check(&parent_of($domain), $user)) {
    return "Access to request $rq not authorized.";
  }

  $sth = $dbh->prepare("SELECT COUNT(*) FROM requests WHERE fqdn=? AND state != 'WaitAck'");
  $sth->execute($domain);
  @row = $sth->fetchrow_array;

  $dbrecords =~ s/\nmnt-by:/\nMNT-BY:/sg;
  $dbrecords =~ s/\nsource:/\nCHANGED: \nsource:/sg;

  return ("", $replyto, $action, $domain, $lang, $state, @row[0],
	  $dns, $dbrecords);
}

sub rq_get_info {
  local ($rq, $user) = ($_[0], $_[1]);
  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  return &rq_db_get_info($dbh, $rq, $user);
}

#
# Delete request
#
sub rq_remove {
  local ($rq, $user, $state) = ($_[0], $_[1], $_[2]);

  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});

  if (!&zauth_check(&parent_of(&rq_db_get_domain($dbh, $rq)), $user)) {
    return "Access to request $rq not authorized.";
  }
  my $sth = $dbh->prepare("UPDATE requests SET state=? WHERE id=?");
  $sth->execute($state, $rq);
  $sth = $dbh->prepare("DELETE FROM requests WHERE id=?");
  $sth->execute($rq);

  return "";
}

sub rq_num {
  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  my $sth = $dbh->prepare("SELECT count(*) FROM requests WHERE state != 'WaitAck'");
  $sth->execute();
  my @rows = $sth->fetchrow_array;
  return @rows[0];
}

#
# Return list of current requests
#
sub rq_list {
  local (@rqlist);
  my ($offset, $limit) = ($_[0], $_[1]);
   
  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  my $sth;

  if ($offset ne '' && $limit ne '') {
    $sth = $dbh->prepare("SELECT id FROM requests WHERE state != 'WaitAck' ORDER BY id OFFSET ? LIMIT ?");
    $sth->execute($offset, $limit);
  } else {
    $sth = $dbh->prepare("SELECT id FROM requests ORDER BY id");
    $sth->execute();
  }

  my @row;
  while (@row = $sth->fetchrow_array) {
    my ($rq) = @row;
    @rqlist = (@rqlist, $rq);
  }
  return @rqlist;
}

#
# Return list of current acked requests for a given domain
#
sub rq_list_dom {
  my (@rqlist);
  my ($domain) = ($_[0]);

  $domain =~ tr/a-z/A-Z/;

  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  my $sth;

  $sth = $dbh->prepare("SELECT id FROM requests WHERE fqdn=? AND state != 'WaitAck' ORDER BY id");
  $sth->execute($domain);

  my @row;
  while (@row = $sth->fetchrow_array) {
    my ($rq) = @row;
    @rqlist = (@rqlist, $rq);
  }
  return @rqlist;
}

#
# Create a new request
#
sub rq_create {
  local ($rq, $replyto, $action, $domain, $lang, $dns, $dbrecords)
	= ($_[0], $_[1], $_[2], $_[3], $_[4], $_[5], $_[6]);

  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  my $sth = $dbh->prepare("INSERT INTO requests (id, email, action, fqdn, language, state, zonerecord, whoisrecord) VALUES (?,?,?,?,?,?,?,?)");
  $sth->execute($rq, $replyto, $action, $domain, $lang, "WaitAck",
	$dns, $dbrecords);
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
  my $dbh = DBI->connect($dbparam, $dbuser, "", {AutoCommit => 1});
  my $sth = $dbh->prepare("SELECT COUNT(*) FROM requests WHERE id=?");
  $sth->execute($rq);
  my @rows = $sth->fetchrow_array;
  return @rows[0];
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
