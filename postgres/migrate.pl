#!/usr/bin/perl
# $Id$

use DBI;
use strict;

my $dbh = DBI->connect("dbi:Pg:dbname=eu.org", "", "", {AutoCommit => 0});
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

# grep -v ^# /local/dns-manager/conf/user-info | awk -F: '{ print "'\''" $1 "'\''=>" ++n "," }'
my %adm = (
'unknown'=>0,
'pb'=>1, 'gb'=>2, 'fcb'=>3, 'roberto'=>4, 'thomas'=>5, 'gdaci'=>6,
'schaefer'=>7, 'regnauld'=>8, 'aj'=>9, 'ck'=>10, 'zop12'=>11, 'patryk'=>12,
'david'=>13, 'rui'=>14, 'rmc'=>15, 'babafou'=>16, 'sam'=>17, 'vladek'=>18,
'jaclavi'=>19, 'pain'=>20, 'ino'=>21, 'jyb'=>22, 'phil'=>23, 'jld'=>24,
'nh'=>25, 'ricou'=>26, 'hrusca'=>27, 'benjamin'=>28, 'olive'=>29, 'erwan'=>30,
'blaudez'=>31, 'ob'=>32, 'lc'=>33,'jertreg'=>34
);

sub parseadm()
{
    my $a = shift;
    my $id = $adm{$a};
    die "Admin '$a' not found" if (!defined($id));
    return $id;
}

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

my $ins_rrs = $dbh->prepare("INSERT INTO rrs (label,rrtype_id,value) VALUES (?,?,?)");
my $ins_domains = $dbh->prepare("INSERT INTO domains (name,zone_id,created_by,created_on,updated_by,updated_on,internal) VALUES (?,currval('zones_id_seq'),?,?,?,?,?)");
my $ins_domain_rr = $dbh->prepare("INSERT INTO domain_rr (domain_id,rr_id) VALUES (currval('domains_id_seq'),currval('rrs_id_seq'))");
my $ins_zone_rr = $dbh->prepare("INSERT INTO zone_rr (zone_id,rr_id,ttl) VALUES (currval('zones_id_seq'),currval('rrs_id_seq'),?)");
my $minlen = 4;
my $maxlen = 24;
my $internal;

open(ZF, "<$file") || die "Cannot open $file: $!";
while (<ZF>) {
	my $ttl;
	chop;
	my $line = "";
	if (/^;! minlen\s+(\d+)/) { $minlen = $1; next }
	if (/^;! maxlen\s+(\d+)/) { $maxlen = $1; next }
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
	if (/^; updated: by (\S+), (.*)$/i) { $upby=&parseadm($1); $upon=&parsetime($2); next }
	if (/^; created: by (\S+), (.*)$/i) { $crby=&parseadm($1); $cron=&parsetime($2); next }
	if (/^\$TTL\s+(\d+)\s*$/) { $soattl = $1; next }
	next if /^;/;
	next if /^\s*$/;
	if (/^(\S+)\s+(.*)$/) {
		$curlabel = uc($1);
		$line = $2;
	} elsif (/^\s+(.*)$/) {
		$line = $1;
	}
	$label = $curlabel;
	if ($label =~ /^(.*)\.$zone\.$/i) { $label = $1; }
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

			my $st = $dbh->prepare("INSERT INTO zones (name,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail,minlen,maxlen) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
			$st->execute($zone,$soattl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail,$minlen,$maxlen);
			#print "INSERT INTO zones (name,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail) VALUES ('$zone',$soattl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,'$soaprimary','$soaemail');\n";
			next;
		} elsif ($type eq 'NS') {
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

	} else {
		print "Cannot parse: $line\n";
		exit 1;
	}
	my $typeid = $rrid{$type};
	if (!defined($rrid{$type})) { die "unhandled RR type: $type\n"; }
	if (defined($ttl) && $domainmode) {
		print "TTL not supported in domain mode, label $curlabel\n";
		exit 1;
	}
	if ($domainmode && defined($domain)) {
		if ($label ne $domain && $label !~ /^(.*)\.$domain$/) { die "Bad label '$label' in domain '$domain'\n"; }
		if ($label eq $domain) { $label = ''; } else { $label = $1; }
	}
	if ($domainmode && !$domain_created) {
		if ($upby eq 0) { $upby=$crby; $upon=$cron; }
		#print "INSERT INTO domains (name,zone_id,created_by,created_on,updated_by,updated_on,internal) VALUES ('$domain',currval('zones_id_seq'),$crby,$cron,$upby,$upon,$internal);\n";
		$ins_domains->execute($domain,$crby,$cron,$upby,$upon,$internal);
		$domain_created=1;
	}
	#print "INSERT INTO rrs (label,rrtype_id,value) VALUES ('$label',$typeid,'$value');\n";
	$ins_rrs->execute($label,$typeid,$value);
	if ($domainmode) {
		#print "INSERT INTO domain_rr (domain_id,rr_id) VALUES (currval('domains_id_seq'),currval('rrs_id_seq'));\n";
		$ins_domain_rr->execute();
	} else {
#	    if (defined($ttl)) {
#		print "INSERT INTO zone_rr (zone_id,rr_id,ttl) VALUES (currval('zones_id_seq'),currval('rrs_id_seq'),$ttl);\n";
#	    } else {
#		print "INSERT INTO zone_rr (zone_id,rr_id) VALUES (currval('zones_id_seq'),currval('rrs_id_seq'));\n";
#	    }
	    $ins_zone_rr->execute($ttl);
	}
}
close ZF;
print "end, commiting...\n";
$dbh->commit;
$dbh->disconnect;
print "done\n";
exit 0;
