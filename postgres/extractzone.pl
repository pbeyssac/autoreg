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

print "\$TTL $ttl\n";
print "$zone.\t$ttl\tSOA\t$soaprimary $soaemail $soaserial $soarefresh $soaretry $soaexpires $soaminimum\n";
$sth = $dbh->prepare("SELECT rrs.label,zone_rr.ttl,rrtypes.label,rrs.value FROM rrs,rrtypes,zone_rr WHERE rrs.id=zone_rr.rr_id AND zone_rr.zone_id=? AND rrtypes.id=rrs.rrtype_id ORDER BY rrs.label");
$sth->execute($zone_id);
while (@row = $sth->fetchrow_array) {
	my ($label,$ttl,$type,$value) = @row;
	if ($label eq "") { die "Error" }
	if (defined($ttl)) { $ttl .= ' ' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label\t$ttl$type\t$value\n";
}

$sth = $dbh->prepare("SELECT rrs.label,domains.name,rrtypes.label,rrs.value FROM domains,rrs,domain_rr,rrtypes WHERE domains.zone_id=? AND rrs.id=domain_rr.rr_id AND domains.id=domain_rr.domain_id AND rrtypes.id=rrs.rrtype_id ORDER BY domains.name");
$sth->execute($zone_id);
while (@row = $sth->fetchrow_array) {
	my ($label,$domain,$type,$value) = @row;
	if ($label ne "") { $label .= '.' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label$domain\t$type\t$value\n";
}

$dbh->disconnect;
exit 0;
