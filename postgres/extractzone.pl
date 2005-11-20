#!/usr/bin/perl
# $Id$

use DBI;
use strict;

my $dbh = DBI->connect("dbi:Pg:dbname=eu.org", "", "", {AutoCommit => 0});
my $sth;
my @row;

my ($label, $curlabel, $type, $value);
my $usermode = 0;

if ($#ARGV ne 0) {
	die "Usage: ".$0." file";
}

my $zone;
my $file = $ARGV[0];
if ($file =~ /\/([^\/]+)$/) {
	$zone = uc($1);
} else {
	$zone = uc($file);
}

$sth = $dbh->prepare("SELECT id,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail FROM zones WHERE name=?");
$sth->execute($zone);
if ($sth->rows < 1) { die "Zone '$zone' not found.\n"; }
if ($sth->rows > 2) { die "Internal error: several zones for '$zone'!\n"; }

@row = $sth->fetchrow_array;
my ($zone_id,$ttl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail) = @row;
print "; zone id=$zone_id\n";
$sth->finish;

if (defined($ttl)) { print "\$TTL $ttl\n"; }
print "$zone.\t$ttl\tSOA\t$soaprimary $soaemail $soaserial $soarefresh $soaretry $soaexpires $soaminimum\n";

$sth = $dbh->prepare("SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value FROM domains,rrs,rrtypes WHERE domains.zone_id=? AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id ORDER BY domains.name,rrs.label");
$sth->execute($zone_id);
while (@row = $sth->fetchrow_array) {
	my ($label,$domain,$ttl,$type,$value) = @row;
	if ($label ne "" && $domain ne "") { $label .= '.' }
	if ("$label$domain" eq "") { $domain = $zone.'.' }
	if ($type eq 'NS' || $type eq 'MX' || $type eq 'CNAME') { $value .= '.' }
	if (defined($ttl)) { $ttl .= " " }
	print "$label$domain\t$ttl$type\t$value\n";
}

$dbh->disconnect;
exit 0;
