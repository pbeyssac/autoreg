#!/usr/bin/perl
# $Id$
#

use DBI;
#use strict;

require "/usr/local/autoreg/conf/config";
require "$DNSLIB/val.pl";

my $dbh = DBI->connect("dbi:PgPP:dbname=eu.org", "", "", {AutoCommit => 1});
my $sth;
my @row;

my (@dirlist) = &rq_list();

my $user = 'autoreg';

$sth = $dbh->prepare("INSERT into requests (id, email, action, fqdn, language, state, zonerecord, whoisrecord) VALUES (?,?,?,?,?,?,?,?)");
foreach $rq (@dirlist) {
    my ($error, $replyto, $action, $domain, $lang,
	$state, $stateinfo, $dns, $dbrecords)
	= &rq_get_info($rq, $user);
    $dbrecords =~ s/\nMNT-BY:/\nmnt-by:/sg;
    $dbrecords =~ s/\nCHANGED: \n/\n/sg;
    print "$rq $domain $state\n";
    $sth->execute($rq, $replyto, $action, $domain, $lang, $state, $dns, $dbrecords);
    if ($sth->rows != 1) { die "INSERT didn't insert 1 row\n"; }
}
$dbh->disconnect;
exit 0;
