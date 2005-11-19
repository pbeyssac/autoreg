#!/usr/bin/perl
# $Id$

# local configuration.
require "/usr/local/dns-manager/conf/config";
require "$DNSLIB/auth.pl";
require "$DNSCONF/msg-access";

use DBI;

#
# Usage:
#  access-zone [-c] [-t type] -u user
#		-a{cat|soa|new|modify|delete|show} domainname
#
# -c -> check only, don't update any file (used for request check)
# -a -> action.
#		cat:	just print out the zone file
#		new:	create the entry for domainname in the parent zone,
#			if not already there
#		modify: modify the entry for domainname in the parent zone,
#			if already there
#		delete: delete the entry for domainname in the parent zone,
#			if already there
#		soa:	update the SOA for domainname in the zonefile of
#			the same name, if the file has previously changed
#			with one of the above actions
#		show:	display the entry for domainname in the parent zone
#
# -u -> username, used to check access permissions with respect to the
#	zones-auth config file
# -t -> type of record (for "new" or "modify"), checked with respect to
#	the ";! type" lines for the types of allowed records in the zone.
#
# For actions "new" and "modify", the records to be inserted are provided
# on stdin.
#

sub myprint {
    local ($handle, @list) = @_;
    if (!print $handle @list) { $err = 1; }
}

sub myprintf {
    local ($handle, @list) = @_;
    if (!printf $handle @list) { $err = 1; }
}

&zauth_read;    

my ($action,$subdom,$parent,$domain);

require "getopts.pl";
&Getopts("ca:u:t:");

if ($opt_a) {
	$action = $opt_a;
	$action =~ tr/A-Z/a-z/;

	if ($action =~ /^n/) {
		$action = 'new';
	} elsif ($action =~ /^m/) {
		$action = 'modify';
	} elsif ($action =~ /^d/) {
		$action = 'delete';
	}
	if ($action eq 'soa') {
		$newsoa = `date +%Y%m%d`; chop $newsoa;
	}
}
if ($opt_t) {
	$type = $opt_t;
	$type =~ tr/a-z/A-Z/;
}

if ($action ne "lock" && $action ne 'unlock'
	 && $action ne 'show'
	 && $action ne 'cat'
	 && $action ne 'soa'
	 && $action ne 'new' && $action ne 'delete' && $action ne 'modify') {
  die("Usage: [-c] [-t type] -u user -a{cat|soa|new|modify|delete|show} domainname\n");
}

if ($#ARGV != 0) {
  die("Usage: [-c] [-t type] -u user -a{cat|soa|new|modify|delete|show} domainname\n");
}

if ($action eq 'soa' || $action eq 'cat') {
  $parent = $ARGV[0];
  $parent =~ tr/a-z/A-Z/;
} else {
  $domain = $ARGV[0];
  $domain =~ tr/a-z/A-Z/;
  $parent=substr($domain, index($domain, ".")+1);
  $subdom=substr($domain, 0, index($domain, "."));
}

my $dbh = DBI->connect("dbi:Pg:dbname=eu.org", "", "", {AutoCommit => 0});
my $st;
my @row;

if ($action eq 'show') {
    $st = $dbh->prepare("SELECT domains.id,created_on,ad1.login,updated_on,ad2.login FROM domains,zones,admins AS ad1,admins AS ad2 WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id AND ad1.id=domains.created_by AND ad2.id=domains.updated_by");
    $st->execute($subdom,$parent);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
    my ($did,$cron,$crby,$upon,$upby) = @row;
    print "; domain $domain\n";
    print "; created: by $crby, $cron\n" if defined($cron);
    print "; updated: by $upby, $upon\n" if defined($upon);
    $st->finish;
    $st = $dbh->prepare("SELECT rrs.label,domains.name,rrtypes.label,rrs.value FROM domains,rrs,domain_rr,rrtypes WHERE domains.id=? AND rrs.id=domain_rr.rr_id AND domains.id=domain_rr.domain_id AND rrtypes.id=rrs.rrtype_id");
    $st->execute($did);
    while (@row = $st->fetchrow_array) {
	my ($label,$domain,$type,$value) = @row;
	if ($label ne "") { $label .= '.' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label$domain\t$type\t$value\n";
    }
    $st->finish;
    $dbh->disconnect;
} elsif ($action eq 'delete') {
    $st = $dbh->prepare("SELECT domains.id,zones_id FROM domains,zones WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id");
    $st->execute($subdom,$parent);
    if ($st->rows < 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
# DELETE FROM domain_rr,rrs
    $st->finish;
} elsif ($action eq 'cat') {
    my $zone = $parent;
    $st = $dbh->prepare("SELECT id,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail FROM zones WHERE name=?");
    $st->execute($zone);
    if ($st->rows < 1) { die "Zone '$zone' not found.\n"; }
    if ($st->rows > 2) { die "Internal error: several zones for '$zone'!\n"; }

    @row = $st->fetchrow_array;
    my ($zone_id,$ttl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail) = @row;
    print "; zone id=$zone_id\n";
    $st->finish;

    print "\$TTL $ttl\n";
    print "$zone.\t$ttl\tSOA\t$soaprimary $soaemail $soaserial $soarefresh $soaretry $soaexpires $soaminimum\n";
    $st = $dbh->prepare("SELECT rrs.label,zone_rr.ttl,rrtypes.label,rrs.value FROM rrs,rrtypes,zone_rr WHERE rrs.id=zone_rr.rr_id AND zone_rr.zone_id=? AND rrtypes.id=rrs.rrtype_id ORDER BY rrs.label");
    $st->execute($zone_id);
    while (@row = $st->fetchrow_array) {
	my ($label,$ttl,$type,$value) = @row;
	if ($label eq "") { die "Error" }
	if (defined($ttl)) { $ttl .= ' ' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label\t$ttl$type\t$value\n";
    }

    $st = $dbh->prepare("SELECT rrs.label,domains.name,rrtypes.label,rrs.value FROM domains,rrs,domain_rr,rrtypes WHERE domains.zone_id=? AND rrs.id=domain_rr.rr_id AND domains.id=domain_rr.domain_id AND rrtypes.id=rrs.rrtype_id ORDER BY domains.name");
    $st->execute($zone_id);
    while (@row = $st->fetchrow_array) {
	my ($label,$domain,$type,$value) = @row;
	if ($label ne "") { $label .= '.' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label$domain\t$type\t$value\n";
    }
}

$dbh->disconnect;
exit 0;
