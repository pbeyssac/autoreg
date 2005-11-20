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
#	the types of allowed records in the zone.
#
# For actions "new" and "modify", the records to be inserted are provided
# on stdin.
#

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
    $st = $dbh->prepare("SELECT rrs.label,domains.name,rrtypes.label,rrs.value FROM domains,rrs,rrtypes WHERE domains.id=? AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id");
    $st->execute($did);
    if ($st->rows == 0) { print "; (NO RECORD)\n"; }
    while (@row = $st->fetchrow_array) {
	my ($label,$domain,$type,$value) = @row;
	if ($label ne "") { $label .= '.' }
	if ($type eq 'NS' || $type eq 'MX') { $value .= '.' }
	print "$label$domain\t$type\t$value\n";
    }
    $st->finish;
    $dbh->commit;
} elsif ($action eq 'modify') {
    $st = $dbh->prepare("SELECT domains.id,zones.id FROM domains,zones WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id FOR UPDATE");
    $st->execute($subdom,$parent);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
    my ($domain_id,$zone_id) = @row;
    $st->finish;
    $st = $dbh->prepare("DELETE FROM domain_rr WHERE domain_id=?");
    $st->execute($domain_id);
    $st->finish;
    $st = $dbh->prepare("DELETE FROM rrs WHERE domain_id=?");
    $st->execute($domain_id);
    $st->finish;

    &insertrr($dbh,$subdom,$zone,$domain_id);

    $st = $dbh->prepare("UPDATE domains SET updated_by=(SELECT id FROM admins WHERE login=?), updated_on=NOW() WHERE id=?");
    $st->execute($opt_u,$domain_id);
    $st->finish;

    $st = $dbh->prepare("UPDATE zones SET updateserial=TRUE WHERE id=?");
    $st->execute($zone_id);
    $st->finish;
    $dbh->commit;
} elsif ($action eq 'delete') {
    $st = $dbh->prepare("SELECT domains.id,zone_id FROM domains,zones WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id FOR UPDATE");
    $st->execute($subdom,$parent);
    if ($st->rows < 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
    my ($domain_id,$zone_id) = @row;
    $st->finish;

    $st = $dbh->prepare("DELETE FROM domain_rr WHERE domain_id=?");
    $st->execute($domain_id);
    $st->finish;
    $st = $dbh->prepare("DELETE FROM rrs WHERE domain_id=?");
    $st->execute($domain_id);
    $st->finish;
    $st = $dbh->prepare("DELETE FROM domains WHERE id=?");
    $st->execute($domain_id);
    $st->finish;
    $st = $dbh->prepare("UPDATE zones SET updateserial=TRUE WHERE id=?");
    $st->execute($zone_id);
    $st->finish;
    $dbh->commit;
} elsif ($action eq 'cat') {
    my $zone = $parent;
    $st = $dbh->prepare("SELECT id,ttl,soaserial,soarefresh,soaretry,soaexpires,soaminimum,soaprimary,soaemail FROM zones WHERE name=?");
    $st->execute($zone);
    if ($st->rows < 1) { die "Zone '$zone' not found.\n"; }
    if ($st->rows > 2) { die "Internal error: several zones for '$zone'!\n"; }

    @row = $st->fetchrow_array;
    my ($zone_id,$ttl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail) = @row;
    print "; zone name=$zone id=$zone_id\n";
    $st->finish;

    print "\$TTL $ttl\n";
    print "$zone.\t$ttl\tSOA\t$soaprimary $soaemail $soaserial $soarefresh $soaretry $soaexpires $soaminimum\n";

    $st = $dbh->prepare("SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value FROM domains,rrs,rrtypes WHERE domains.zone_id=? AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id ORDER BY domains.name,rrs.label");
    $st->execute($zone_id);
    while (@row = $st->fetchrow_array) {
	my ($label,$domain,$ttl,$type,$value) = @row;
	if ($label ne "" && $domain ne "") { $label .= '.' }
	if ("$label$domain" eq "") { $domain = $zone.'.' }
	if ($type eq 'NS' || $type eq 'MX' || $type eq 'CNAME') { $value .= '.' }
	if (defined($ttl)) { $ttl .= " " }
	print "$label$domain\t$ttl$type\t$value\n";
    }
    $dbh->commit;
} elsif ($action eq 'soa') {
    my $zone = $parent;
    $st = $dbh->prepare("SELECT id,soaserial,updateserial FROM zones WHERE name=? FOR UPDATE");
    $st->execute($zone);
    if ($st->rows < 1) { die "Zone '$zone' not found.\n"; }
    if ($st->rows > 2) { die "Internal error: several zones for '$zone'!\n"; }

    @row = $st->fetchrow_array;
    my ($zone_id,$soaserial,$updateserial) = @row;
    $st->finish;

    if (!$updateserial) {
	$dbh->commit;
	exit 1;
    }
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    my $newserial = sprintf("%04d%02d%02d00", $year+1900, $mon+1, $mday);
    if ($newserial le $soaserial) { $newserial = $soaserial+1 }
    $st = $dbh->prepare("UPDATE zones SET soaserial=?, updateserial=FALSE WHERE id=?");
    $st->execute($newserial,$zone_id);
    $st->finish;
    $dbh->commit;
}

$dbh->disconnect;
exit 0;

#
# Insert a set of RRs obtained from STDIN
#
sub insertrr()
{
    my $dbh = shift;
    my $subdom = shift;
    my $zone = shift;
    my $domain_id = shift;
    my $label;
    my $ins_rrs = $dbh->prepare("INSERT INTO rrs (domain_id,label,ttl,rrtype_id,value) VALUES (?,?,?,(SELECT id FROM rrtypes WHERE label=?),?)");
    my $ins_domain_rr = $dbh->prepare("INSERT INTO domain_rr (domain_id,rr_id) VALUES (?,currval('rrs_id_seq'))");

    while (<STDIN>) {
	my ($ttl, $type, $value);
	chop;
	my $line = $_;

	# skip comment lines
	next if /^\s*;/;
	next if /^\s*$/;

	# get label, if any
	if (/^(\S+)\s+(.*)$/) {
	    $label = uc($1);
	    $line = $2;
	} elsif (/^\s+(.*)$/) {
	    $line = $1;
	} else {
	    die "Cannot parse: $line\n";
	}

	# handle label
	if ($label =~ /^(.*)\.$zone\.$/i) { $label = $1; }
	elsif ($label =~ /^$zone\.$/i) { $label = ''; }
	elsif ($label =~ /^(.*)\.$subdom$/i) { $label = $1; }
	elsif ($label eq $subdom) { $label = ''; }

	# get ttl, if any
	if ($line =~ /^(\d+)\s+(.*)$/) { $ttl = $1; $line = $2; }

	# skip IN class keyword, if present
	if ($line =~ /^IN\s+(.*)$/) { $line = $1; }

	# try to parse RR type and value
	if ($line =~ /(\S+)\s+(.*)$/) {
	    $type = uc($1);
	    $value = $2;
	    if ($value =~ /^(.*\S)\s+$/) { $value = $1; }
	    if ($type eq 'NS' || $type eq 'CNAME') {
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
	    else {
		die "Unsupported RR type: $type\n";
	    }
	} else {
	    die "Cannot parse: $line\n";
	}

	# all done, insert in database
	$ins_rrs->execute($domain_id,$label,$ttl,$type,$value);
	# domain_rr will probably be deprecated someday
	$ins_domain_rr->execute($domain_id);
    }
}
