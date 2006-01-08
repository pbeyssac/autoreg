#!/usr/bin/perl
# $Id$
#
# Zone migration script, deprecated -- DOT NOT RUN
#

use DBI;
use strict;

my $dbh = DBI->connect("dbi:Pg:dbname=eudevel", "", "", {AutoCommit => 0});
my $sth;
my @row;

#$sth = $dbh->prepare("SELECT domains.name, zones.name FROM domains,zones WHERE domains.zone_id=zones.id");
#$sth->execute();
#while (@row = $sth->fetchrow_array) {
#	print $row[0].".".$row[1]."\n";
#}
#$dbh->disconnect;
#exit 0;

my ($label, $curlabel, $type, $value);
my $domainmode = 0;

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

my %rrid = (
	'NS'=>1, 'MX'=>2, 'A'=>3, 'CNAME'=>4, 'AAAA'=>5,
	'TXT'=>6, 'SRV'=>7, 'HINFO'=>8
);
my %domains;

sub parsetime()
{
    my $c = shift;
    my %m = ( 'jan'=>0, 'feb'=>1, 'mar'=>2, 'apr'=>3, 'may'=>4, 'jun'=>5,
	'jul'=>6, 'aug'=>7, 'sep'=>8, 'oct'=>9, 'nov'=>10, 'dec'=>11,
	'fev'=>1, 'fév'=>1, 'avr'=>3, 'mai'=>4, 'jui'=>5, 'jul'=>6,
	'aou'=>7, 'aoû'=>7, 'déc'=>11, 'juin'=>5 );
    my ($mon, $mday, $hh, $mm, $ss, $tz, $year, $mo);
    $c =~ s/\s+$//;
    if ($c =~ /^(\S\S\S )?(\S\S\S)\s+(\d\d?) (\d\d):(\d\d):(\d\d) (\S+( \S+)?) (\d\d\d\d)$/i) {
	$mon = $2;
	$mday = $3;
	$hh = $4;
	$mm = $5;
	$ss = $6;
	$tz = $7;
	$year = $9;
	$mo = $m{lc($mon)};
	if (!defined($mo)) { die "Invalid month: '$mon'"; }
    } elsif ($c =~ /^\S\S\S ([ \d]\d) (\S\S\S+) (\d\d\d\d) (\d\d):(\d\d):(\d\d) (\S+)$/i) {
	$mday = $1;
	$mon = $2;
	$year = $3;
	$hh = $4;
	$mm = $5;
	$ss = $6;
	$tz = $7;
	$mo = $m{lc($mon)};
	if (!defined($mo)) { die "Invalid month: '$mon'"; }
    } elsif ($c =~ /^(\d\d\d\d)-?(\d\d)-?(\d\d)$/) {
	$year = $1;
	$mo = $2-1;
	$mday = $3;
	$hh = 0; $mm = 0; $ss = 0;
    } else {
	die "Cannot parse: '$c'\n";
    }
    #print sprintf("%04d-%02d-%02d %02d:%02d:%02d\n", $year, $mo+1, $mday, $hh, $mm, $ss);
    return "'".sprintf("%04d-%02d-%02d %02d:%02d:%02d", $year, $mo+1, $mday, $hh, $mm, $ss)."'";
}

my ($domain,$crby,$upby,$cron,$upon,$domain_created);
my ($soaprimary, $soaemail, $soaserial, $soarefresh, $soaretry, $soaexpires, $soaminimum);
my $soattl;
my $origin = $zone.'.';

my $ins_rrs = $dbh->prepare("INSERT INTO rrs (domain_id,label,ttl,rrtype_id,value) VALUES (currval('domains_id_seq'),?,?,?,?)");
my $ins_domains = $dbh->prepare("INSERT INTO domains (name,zone_id,created_by,created_on,updated_by,updated_on,internal) VALUES (?,currval('zones_id_seq'),(SELECT id FROM admins WHERE login=?),?,(SELECT id FROM admins WHERE login=?),?,?)");
my $ins_allowed_rr = $dbh->prepare("INSERT INTO allowed_rr (zone_id,rrtype_id) VALUES (currval('zones_id_seq'),(SELECT id FROM rrtypes WHERE label=?))");
my $minlen = 4;
my $maxlen = 24;
my $internal;
my %allowed_rr;
my $ndom = 0;
my $nrr = 0;

open(ZF, "<$file") || die "Cannot open $file: $!";
while (<ZF>) {
	my $ttl;
	chop;
	my $line = "";

	if (/^;! minlen\s+(\d+)/) { $minlen = $1; next }
	if (/^;! maxlen\s+(\d+)/) { $maxlen = $1; next }
	if (/^;! type\s+(\S+)/) { $allowed_rr{uc($1)} = 1; next }
	if (/^; BEGINNING OF USER-DELEGATED DOMAINS/) { $domainmode = 1; next }
	if (/^; (i?)domain (\S+)$/) {
		$internal = 0;
		if ($1 eq 'i') { $internal = 1 }
		$domainmode=1;
		$domain_created=0;
		$upby = 0; $crby = 0;
		$upon = undef; $cron = undef;
		$domain = uc($2);
		if ($domain =~ /^(.*)\.$zone\.$/i) { $domain = $1; }
		next
	}
	if (/^; updated: by (\S+), (.*)$/i) { $upby=$1; $upon=&parsetime($2); next }
	if (/^; created: by (\S+), (.*)$/i) { $crby=$1; $cron=&parsetime($2); next }
	if (/^\$TTL\s+(\d+)\s*$/) { $soattl = $1; next }
	if (/^\$ORIGIN\s+(\S+)\s*$/) { $origin = $1; next }
	next if /^\s*;/;
	next if /^\s*$/;
	if (/^(\S+)\s+(.*)$/) {
		$curlabel = uc($1);
		$line = $2;
	} elsif (/^\s+(.*)$/) {
		$line = $1;
	} else {
		die "Cannot parse: $line\n";
	}
	$label = $curlabel;
	if ($label eq '@') { $label = ""; }
	elsif ($label =~ /^(.*)\.$zone\.$/i) { $label = $1; }
	if ($line =~ /^(\d+)\s+(.*)$/) {
		$ttl = $1;
		$line = $2;
	}
	if ($line =~ /^IN\s+(.*)$/) {
		$line = $1;
	}
	if ($line =~ /(\S+)\s+(.*)$/) {
		$type = uc($1);
		$value = $2;
		if ($value =~ /^(.*\S)\s+$/) { $value = $1; }
		if ($type eq 'SOA') {
			if ($value !~ /^(\S+)\s+(\S+)\s+\(\s*$/) { die "Bad SOA line: $value\n"; }
			$soaprimary = $1;
			$soaemail = $2;
			$line = <ZF>; if ($line !~ /^\s+(\d+)\s*;\s*serial/i) { die "Bad SOA serial: $line"; }
			$soaserial = $1;
			$line = <ZF>; if ($line !~ /^\s+(\d+)\s*;\s*refresh/i) { die "Bad SOA refresh: $line"; }
			$soarefresh = $1;
			$line = <ZF>; if ($line !~ /^\s+(\d+)\s*;\s*retry/i) { die "Bad SOA retry: $line"; }
			$soaretry = $1;
			$line = <ZF>; if ($line !~ /^\s+(\d+)\s*;\s*expires/i) { die "Bad SOA expires: $line"; }
			$soaexpires = $1;
			$line = <ZF>; if ($line !~ /^\s+(\d+)\s*\)\s*;\s*minimum/i) { die "Bad SOA minimum: $line"; }
			$soaminimum = $1;

			my $st = $dbh->prepare("SELECT id FROM zones WHERE name=? FOR UPDATE");
			$st->execute($zone);
			if ($st->rows > 1) { die "Internal error: several zones with name='$zone'\n"; }

			$| = 1;
			print "Zone $zone: ";

			if ($st->rows == 1) {
			    my @rows = $st->fetchrow_array;
			    my ($zone_id) = @rows;
			    print "cleaning up zone (id $zone_id) and history...";
			    $st = $dbh->prepare("DELETE FROM rrs WHERE domain_id IN (SELECT id FROM domains WHERE zone_id=?)");
			    $st->execute($zone_id);
			    $st = $dbh->prepare("DELETE FROM domains WHERE zone_id=?");
			    $st->execute($zone_id);
			    $st = $dbh->prepare("DELETE FROM allowed_rr WHERE zone_id=?");
			    $st->execute($zone_id);
			    $st = $dbh->prepare("DELETE FROM rrs_hist WHERE domain_id IN (SELECT id FROM domains_hist WHERE zone_id=?)");
			    $st->execute($zone_id);
			    $st = $dbh->prepare("DELETE FROM domains_hist WHERE zone_id=?");
			    $st->execute($zone_id);
			    $st = $dbh->prepare("DELETE FROM zones WHERE id=?");
			    $st->execute($zone_id);
			}
			$st->finish;

			print "loading...";
			$st = $dbh->prepare("INSERT INTO zones (name,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail,minlen,maxlen,updateserial) VALUES (?,?,?,?,?,?,?,?,?,?,?,FALSE)");
			$st->execute($zone,$soattl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail,$minlen,$maxlen);
			foreach my $t (keys %allowed_rr) {
			    $ins_allowed_rr->execute(uc($t));
			}
			$ins_domains->execute("",undef,undef,undef,undef,1);
			next;
		} elsif ($type eq 'NS' || $type eq 'CNAME') {
			$value = uc($value);
			die "Not dot-terminated: $curlabel $value" if ($value !~ /\.$/);
			chop $value;
		} elsif ($type eq 'MX') {
			$value = uc($value);
			if ($value !~ /^(\d+)\s+(\S+)$/) {
				die "Bad syntax for MX record: $value";
			}
			$value = "$1 $2";
			die "Not dot-terminated: $curlabel $value" if ($value !~ /\.$/);
			chop $value;
		}
		elsif ($type eq 'SRV') { $value = uc($value); }
		elsif ($type eq 'AAAA') { $value = uc($value); }
		elsif ($type eq 'A') { }
		elsif ($type eq 'TXT') { }
		elsif ($type eq 'HINFO') { }
		else { die "Unsupported RR type: $type\n"; }
	} else {
		print "Cannot parse: $line\n";
		exit 1;
	}
	my $typeid = $rrid{$type};
	if (!defined($rrid{$type})) { die "unhandled RR type: $type\n"; }
	if (defined($ttl) && $domainmode && !$internal) {
		print "TTL not supported in domain mode, label $curlabel\n";
		exit 1;
	}
	if ($domainmode && defined($domain)) {
		if ($label ne $domain && $label !~ /^(.*)\.$domain$/) { die "Bad label '$label' in domain '$domain'\n"; }
		if ($label eq $domain) { $label = ''; } else { $label = $1; }
	}
	if ($domainmode && !$domain_created) {
		if ($upby eq 0) { $upby=$crby; $upon=$cron; }
		if (defined($domains{$domain})) {
		    die "Duplicate domain entry: '$domain', aborting.\n";
		}
		$domains{$domain} = 1;
		$ins_domains->execute($domain,$crby,$cron,$upby,$upon,$internal);
		$ndom++;
		$domain_created=1;
	}
	$ins_rrs->execute($label,$ttl,$typeid,$value);
	$nrr++;
}
close ZF;
$dbh->commit;
print "done. $ndom domains, $nrr resource records.\n";
$dbh->disconnect;
exit 0;
