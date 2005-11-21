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
    $st = $dbh->prepare("SELECT domains.id,created_on,ad1.login,updated_on,ad2.login,registry_lock,registry_hold,internal FROM domains,zones,admins AS ad1,admins AS ad2 WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id AND ad1.id=domains.created_by AND ad2.id=domains.updated_by");
    $st->execute($subdom,$parent);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
    my ($did,$cron,$crby,$upon,$upby,$registry_lock,$registry_hold,$internal) = @row;
    print "; domain $domain\n";
    print "; created: by $crby, $cron\n" if defined($cron);
    print "; updated: by $upby, $upon\n" if defined($upon);
    if ($registry_lock) { print "; registry_lock\n" }
    if ($registry_hold) { print "; registry_hold\n" }
    if ($internal) { print "; internal\n" }
    $st->finish;
    $st = $dbh->prepare("SELECT rrs.label,domains.name,rrtypes.label,rrs.value FROM domains,rrs,rrtypes WHERE domains.id=? AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id");
    $st->execute($did);
    if ($st->rows == 0) { print "; (NO RECORD)\n"; }
    while (@row = $st->fetchrow_array) {
	my ($label,$domain,$type,$value) = @row;
	if ($label ne "") { $label .= '.' }
	if ($type eq 'NS' || $type eq 'MX' || $type eq 'CNAME') { $value .= '.' }
	print "$label$domain\t$type\t$value\n";
    }
    $st->finish;
    $dbh->commit;
} elsif ($action eq 'new') {
    if (!&zauth_check($parent, $opt_u)) {
	$dbh->disconnect;
	die sprintf($MSG_NUSER, $opt_u);
    }
    $st = $dbh->prepare("SELECT zones.id,minlen,maxlen FROM zones WHERE zones.name=? FOR UPDATE");
    $st->execute($parent);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die "Zone $parent unknown";
    }
    @row = $st->fetchrow_array;
    my ($zone_id,$minlen,$maxlen) = @row;
    $st->finish;

    $st = $dbh->prepare("SELECT id FROM domains WHERE name=? AND zone_id=?");
    $st->execute($subdom,$zone_id);
    if ($st->rows != 0) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_ALLOC, $domain);
    }
    $st->finish;

    $st = $dbh->prepare("SELECT zone_id,rrtype_id FROM allowed_rr WHERE allowed_rr.zone_id=? AND allowed_rr.rrtype_id=(SELECT id FROM rrtypes WHERE rrtypes.label=?)");
    $st->execute($zone_id,$type);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NOTYP, $type);
    }
    $st->finish;

    if (length($subdom) < $minlen) {
	$dbh->disconnect;
	die sprintf($MSG_SHORT, $parent, $minlen);
    }
    if (length($subdom) > $maxlen) {
	$dbh->disconnect;
	die sprintf($MSG_LONG, $parent, $maxlen);
    }

    $st = $dbh->prepare("INSERT INTO domains (name,zone_id,created_by,created_on,updated_by,updated_on,internal) VALUES (?,?,(SELECT id FROM admins WHERE login=?),NOW(),(SELECT id FROM admins WHERE login=?),NOW(),FALSE)");
    $st->execute($subdom,$zone_id,$opt_u,$opt_u);
    $st->finish;

    $st = $dbh->prepare("SELECT currval('domains_id_seq')");
    $st->execute();
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die "Internal error when creating domain $subdom.$parent\n";
    }
    @row = $st->fetchrow_array;
    my ($domain_id) = @row;
    &insertrr($dbh,$subdom,$zone,$domain_id);

    $st = $dbh->prepare("UPDATE zones SET updateserial=TRUE WHERE id=?");
    $st->execute($zone_id);
    $st->finish;
    $dbh->commit;
} elsif ($action eq 'modify') {
    if (!&zauth_check($parent, $opt_u)) {
	$dbh->disconnect;
	die sprintf($MSG_NUSER, $opt_u);
    }
    $st = $dbh->prepare("SELECT domains.id,zones.id,registry_lock,internal FROM domains,zones WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id FOR UPDATE");
    $st->execute($subdom,$parent);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NODOM, $domain, $action);
    }
    @row = $st->fetchrow_array;
    my ($domain_id,$zone_id,$registry_lock,$internal) = @row;
    $st->finish;

    if ($registry_lock || $internal) {
	$dbh->disconnect;
	die sprintf($MSG_LOCKD, $domain);
    }

    $st = $dbh->prepare("SELECT zone_id,rrtype_id FROM allowed_rr WHERE allowed_rr.zone_id=? AND allowed_rr.rrtype_id=(SELECT id FROM rrtypes WHERE rrtypes.label=?)");
    $st->execute($zone_id,$type);
    if ($st->rows != 1) {
	$st->finish;
	$dbh->disconnect;
	die sprintf($MSG_NOTYP, $type);
    }
    $st->finish;

    # save history
    $st = $dbh->prepare("INSERT INTO rrs_hist (domain_id,ttl,rrtype_id,created_on,label,value,deleted_on) SELECT domain_id,ttl,rrtype_id,created_on,label,value,NOW() FROM rrs WHERE domain_id=?");
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
} elsif ($action eq 'lock' || $action eq 'unlock') {
    if (!&zauth_check($parent, $opt_u)) {
	$dbh->disconnect;
	die sprintf($MSG_NUSER, $opt_u);
    }

    my $lock = 1;
    if ($action eq 'unlock') { $lock = 0 }

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

    $st = $dbh->prepare("UPDATE domains SET registry_lock=? WHERE id=?");
    $st->execute($lock, $domain_id);
    $st->finish;

    $dbh->commit;
} elsif ($action eq 'delete') {
    if (!&zauth_check($parent, $opt_u)) {
	$dbh->disconnect;
	die sprintf($MSG_NUSER, $opt_u);
    }
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

    # save history
    $st = $dbh->prepare("INSERT INTO rrs_hist (domain_id,ttl,rrtype_id,created_on,label,value,deleted_on) SELECT domain_id,ttl,rrtype_id,created_on,label,value,NOW() FROM rrs WHERE domain_id=?");
    $st->execute($domain_id);
    $st->finish;
    $st = $dbh->prepare("INSERT INTO domains_hist (id,name,zone_id,registrar_id,created_by,created_on,deleted_by,deleted_on) SELECT id,name,zone_id,registrar_id,created_by,created_on,(SELECT id FROM admins WHERE login=?),NOW() FROM domains WHERE id=?");
    $st->execute($opt_u,$domain_id);
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
    if ($st->rows < 1) {
	$dbh->disconnect;
	die "Zone '$zone' not found.\n";
    }
    if ($st->rows > 2) {
	$dbh->disconnect;
	die "Internal error: several zones for '$zone'!\n";
    }

    @row = $st->fetchrow_array;
    my ($zone_id,$ttl,$soaserial,$soarefresh,$soaretry,$soaexpires,$soaminimum,$soaprimary,$soaemail) = @row;
    print "; zone name=$zone id=$zone_id\n";
    $st->finish;

    if (defined($ttl)) { print "\$TTL $ttl\n"; }
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
    if ($st->rows < 1) {
	$dbh->disconnect;
	die "Zone '$zone' not found.\n";
    }
    if ($st->rows > 2) {
	$dbh->disconnect;
	die "Internal error: several zones for '$zone'!\n";
    }

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
	    $dbh->disconnect;
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
		if ($value !~ /\.$/) {
		    $dbh->disconnect;
		    die "Not dot-terminated: $curlabel $value"
		}
		chop $value;
	    } elsif ($type eq 'MX') {
		$value = uc($value);
		if ($value !~ /^(\d+)\s+(\S+)$/) {
		    $dbh->disconnect;
		    die "Bad syntax for MX record: $value";
		}
		$value = "$1 $2";
		if ($value !~ /\.$/) {
		    $dbh->disconnect;
		    die "Not dot-terminated: $curlabel $value";
		}
		chop $value;
	    }
	    elsif ($type eq 'SRV') { $value = uc($value); }
	    elsif ($type eq 'AAAA') { $value = uc($value); }
	    elsif ($type eq 'A') { }
	    elsif ($type eq 'TXT') { }
	    else {
		$dbh->disconnect;
		die "Unsupported RR type: $type\n";
	    }
	} else {
	    $dbh->disconnect;
	    die "Cannot parse: $line\n";
	}

	# all done, insert in database
	$ins_rrs->execute($domain_id,$label,$ttl,$type,$value);
    }
}
