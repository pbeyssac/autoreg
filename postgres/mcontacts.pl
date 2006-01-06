#!/usr/bin/perl
# $Id$

use DBI;
use strict;

my $dbh = DBI->connect("dbi:Pg:dbname=eudevel", "", "", {AutoCommit => 0});
my $sth;

if ($#ARGV ne 0) {
	die "Usage: ".$0." file";
}

my $file = $ARGV[0];

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
    } elsif ($c =~ /^(\d\d\d\d)(\d\d)(\d\d)$/) {
	$year = $1;
	$mo = $2-1;
	$mday = $3;
	$hh = 0; $mm = 0; $ss = 0;
    } elsif ($c =~ /^(\d\d)(\d\d)(\d\d)$/) {
	if ($1 > 50) { $year = $1 + 1900; } else { $year = $1 + 2000; }
	$mo = $2-1;
	$mday = $3;
	$hh = 0; $mm = 0; $ss = 0;
    } else {
	die "Cannot parse: '$c'\n";
    }
    #print sprintf("%04d-%02d-%02d %02d:%02d:%02d\n", $year, $mo+1, $mday, $hh, $mm, $ss);
    return "'".sprintf("%04d-%02d-%02d %02d:%02d:%02d", $year, $mo+1, $mday, $hh, $mm, $ss)."'";
}

sub dumpobj()
{
    my (%attr) = @_;
    foreach my $i (sort keys %attr) {
	print "$i: $attr{$i}\n";
    }
    print "\n";
}

my $ndom = 0;
my $nperson = 0;
my $nambig = 0;
my $ninval = 0;
my %attr;
my %dom;

my $sel_domain = $dbh->prepare("SELECT domains.id FROM domains,zones WHERE domains.name=? AND zones.name=? AND domains.zone_id=zones.id FOR UPDATE");
my $ins_contacts = $dbh->prepare("INSERT INTO contacts (handle,name,email,addr1,addr2,addr3,addr4,addr5,addr6,phone,fax,updated_on) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
my $ins_domain_dummy = $dbh->prepare("INSERT INTO domains (name,zone_id) VALUES (?,(SELECT id FROM zones WHERE name=?))");
my $sel_domain_id = $dbh->prepare("SELECT currval('domains_id_seq')");
my $ins_dc = $dbh->prepare("INSERT INTO domain_contact (domain_id,contact_id,contact_type_id) VALUES (?,(SELECT currval('contacts_id_seq')),(SELECT id FROM contact_types WHERE name=?))");
my $ins_dc2 = $dbh->prepare("INSERT INTO domain_contact (domain_id,contact_id,contact_type_id) (SELECT ?,id,(SELECT id FROM contact_types WHERE name=?) FROM contacts WHERE (lower(name)=? OR handle=?) AND email IS NOT NULL)");

my $del_dc = $dbh->prepare("DELETE FROM domain_contact");
$del_dc->execute();
$del_dc->finish();
my $del_contacts = $dbh->prepare("DELETE FROM contacts");
$del_contacts->execute();
$del_contacts->finish();

my %shorts = ('person'=>'pn', 'address'=>'ad', 'tech-c'=>'tc', 'admin-c'=>'ac',
	'phone'=>'ph', 'fax'=>'fx', 'e-mail'=>'em', 'changed'=>'ch',
	'remark'=>'rm', 'nic-hdl'=>'nh', 'notify'=>'ny', 'mnt-by'=>'mb',
	'source'=>'so', 'upd->to'=>'dt', 'auth'=>'at', 'mntner'=>'mt',
	'domain'=>'dn'
);

sub ins_person()
{
    my %attr = @_;
    my $ts = $attr{'ch0'};
    if ($ts =~ /^\S+\s+(\d+)$/) { $ts = &parsetime($1); }
    else { undef $ts };
    $ins_contacts->execute(uc($attr{'nh0'}),
	$attr{'pn0'},
	$attr{'em0'},
	$attr{'ad0'}, $attr{'ad1'}, $attr{'ad2'},
	$attr{'ad3'}, $attr{'ad4'}, $attr{'ad5'},
	$attr{'ph0'}, $attr{'fx0'},
	$ts);
    foreach my $i ('pn1', 'em1', 'ad6', 'rm2', 'ph1', 'fx1', 'ch1') {
	if (defined $attr{$i}) {
	    print "person $attr{'pn0'}: unhandled attribute $i\n";
	    &dumpobj(%attr);
	}
    }
}

sub ins_domain()
{
    my $attr = shift;
    my $ts = $$attr{'ch0'};
    my $dn = uc($$attr{'dn0'});
    my @d = split(/\./, $dn);
    my $n = @d;

    if ($ts =~ /^\S+\s+(\d+)$/) { $ts = &parsetime($1); }
    else { undef $ts };

    my ($domain_id, $d, $z);

    #
    # Try to find domain and zone
    #
    my @p1;
    my @p2 = @d;
    for (my $i; $i < $n; $i++) {
	push @p1, shift @p2;
	($d, $z) = (join('.',@p1), join('.',@p2));
	$sel_domain->execute($d,$z);
	if ($sel_domain->rows > 1) { die "Several domains match for d=$d z=$z\n"; }
	if ($sel_domain->rows == 1) {
	    my @row = $sel_domain->fetchrow_array;
	    ($domain_id) = @row;
	    last;
	}
    }

    if (!defined($domain_id)) {
	print "Domain $dn not handled in DNS, inserting as dummy domain\n";
	$ins_domain_dummy->execute($dn, '');
	$sel_domain_id->execute();
	if ($sel_domain_id->rows != 1) {
	    die "Internal error while getting domain_id\n";
	}
	my @row = $sel_domain_id->fetchrow_array;
	($domain_id) = @row;
    }

    $ins_contacts->execute(undef,
	$$attr{'ad0'},
	undef,
	$$attr{'ad1'}, $$attr{'ad2'}, $$attr{'ad3'},
	$$attr{'ad4'}, $$attr{'ad5'}, $$attr{'ad6'},
	undef, undef,
	$ts);
    foreach my $i ('pn0', 'em0', 'ad7', 'rm0', 'ph0', 'fx0', 'ch1') {
	if (defined $$attr{$i}) {
	    print "domain $$attr{'dn0'}: unhandled attribute $i\n";
	    # &dumpobj(%attr);
	}
    }

    foreach my $i ('tc', 'zc', 'ac') {
	my $j = 0;
	my $c;
	if ($i eq 'tc') { $c = 'technical' }
	elsif ($i eq 'zc') { $c = 'zone' }
	elsif ($i eq 'ac') { $c = 'administrative' }
	while (defined($$attr{$i.$j})) {
	    $ins_dc2->execute($domain_id, $c, lc($$attr{$i.$j}),uc($$attr{$i.$j}));
	    my $r = $ins_dc2->rows;
	    if ($r == 0) {
		print "Warning: invalid $c contact '$$attr{$i.$j}', domain $dn\n";
		$ninval++;
	    } elsif ($r > 1) {
		print "Warning: ambiguous $c contact '$$attr{$i.$j}', domain $dn\n";
		$nambig++;
	    }
	    $j++;
	}
    }
    $ins_dc->execute($domain_id, 'registrant');
}

sub ins_obj()
{
    my %attr = @_;
    if (defined $attr{'dn0'}) {
	$ndom++;
	# &ins_domain(%attr);
	$dom{uc($attr{'dn0'})} = \%attr;
    } elsif (defined $attr{'mt0'}) {
    } elsif (defined $attr{'pn0'}) {
	$nperson++;
	&ins_person(%attr);
    } elsif (defined $attr{'XX0'}) {
	# deleted object, ignore
    } else {
	print "Unknown object type\n";
	&dumpobj(%attr);
	exit 1;
    }
}

my $gotattr = 0;
open(CF, "<$file") || die "Cannot open $file: $!";
while (<CF>) {
    next if (/^\s*#/);
    if (/^\s*$/ && $gotattr) {
	&ins_obj(%attr);
	undef %attr;
	$gotattr = 0;
	next;
    } elsif (/^$/) {
	next;
    }
    my ($a, $v);
    if (/^([a-z]+):\s+(.*\S)\s*$/i) {
	($a, $v) = ($1, $2);
	if (defined($shorts{$a})) {
	    $a = $shorts{$a};
	}
    }
    if (/^\*([a-z][a-z]):\s+(.*\S)\s*$/i) {
	($a, $v) = ($1, $2);
    }
    if (defined($a)) {
	my $i;
	for ($i = 0; $i < 9; $i++) {
	    last if (!defined $attr{"$a$i"});
	}
	$attr{"$a$i"} = $v;
	$gotattr++;
	next;
    }
    die "Cannot parse line: $_\n";
}
if ($gotattr) { &ins_obj(%attr); }
close CF;
foreach my $i (sort keys %dom) {
    my $a = $dom{$i};
    &ins_domain($a);
}

$sel_domain->finish();
$sel_domain_id->finish();
$dbh->commit;
print "$ndom domains, $nperson persons.\n";
print "$nambig ambiguous, $ninval invalid contacts.\n";
$dbh->disconnect;
exit 0;
