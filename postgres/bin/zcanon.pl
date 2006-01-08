#!/usr/bin/perl
# $Id$

use strict;

my ($label, $curlabel, $type, $value);
my $usermode = 0;

if ($#ARGV ne 1) {
	die "Usage: ".$0."zone file";
}

my $zone = uc(shift @ARGV);

my %rr;
my %rrid = (
	'SOA'=>0,
	'NS'=>1, 'MX'=>2, 'A'=>3, 'CNAME'=>4, 'AAAA'=>5,
	'TXT'=>6, 'SRV'=>7, 'HINFO'=>8
);

sub parsettl ()
{
    my $ttl = shift;
    my $s = 0;
    while ($ttl ne '') {
	if ($ttl =~ /^(\d+)W(.*)$/i) {
	    $s += $1 * 86400*7;
	    $ttl = $2;
	    next
	}
	if ($ttl =~ /^(\d+)D(.*)$/i) {
	    $s += $1 * 86400;
	    $ttl = $2;
	    next
	}
	if ($ttl =~ /^(\d+)H(.*)$/i) {
	    $s += $1 * 3600;
	    $ttl = $2;
	    next
	}
	if ($ttl =~ /^(\d+)M(.*)$/i) {
	    $s += $1 * 60;
	    $ttl = $2;
	    next
	}
	if ($ttl =~ /^(\d+)(.*)$/i) {
	    $s += $1;
	    $ttl = $2;
	    next
	}
	return undef;
    }
    return $s;
}

my ($origin);
my ($domain,$crby,$upby,$cron,$upon,$domain_created);
my ($soaprimary, $soaemail, $soaserial, $soarefresh, $soaretry, $soaexpires, $soaminimum);
my $soattl;

$origin = $zone.'.';

#open(ZF, "<$file") || die "Cannot open $file: $!";
while (<>) {
	my $ttl;
	chop;
	my $line = "";
	if (/^\$ORIGIN\s+(\S+)\s*$/) {
	    my $neworigin = uc($1);
	    if ($neworigin !~ /\.$/) { $neworigin .= '.'.$origin; }
	    $origin = $neworigin;
	    next
	}
	if (/^\$TTL\s+(\S+)\s*$/) { $soattl = $1; next }
	next if /^;/;
	next if /^\s*$/;
	if (/^(\S+)\s+(.*)$/) {
		$label = uc($1);
		$line = $2;
	} elsif (/^\s+(.*)$/) {
		$line = $1;
	}
	if ($label eq '@') { $label = $origin; }
	if ($label !~ /\.$/) { $label .= '.'.$origin; }
	$ttl = $soattl;
	if ($line =~ /^(\S+)\s+(.*)$/) {
	    my $t = &parsettl($1);
	    if (defined($t)) {
		$ttl = $t;
		$line = $2;
	    }
	}
	if ($line =~ /^IN\s+(.*)$/i) { $line = $1; }
	if ($line =~ /(\S+)\s+(.*)$/) {
	    $type = uc($1);
	    $value = $2;
	    if ($value =~ /^(.*\S)\s+$/) { $value = $1; }
	    if ($type eq 'SOA') {
		if ($value =~ /^(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$/) {
		    $soaprimary = $1;
		    $soaemail = $2;
		    $soaserial = $3;
		    $soarefresh = &parsettl($4);
		    $soaretry = &parsettl($5);
		    $soaexpires = &parsettl($6);
		    $soaminimum = &parsettl($7);
		} elsif ($value =~ /^(\S+)\s+(\S+)\s+\(\s*$/) {
		    $soaprimary = $1;
		    $soaemail = $2;
		    $line = <>; if ($line !~ /^\s+(\d+)\s*;\s*serial/i) { die "Bad SOA serial: $line"; }
		    $soaserial = $1;
		    $line = <>; if ($line !~ /^\s+(\S+)\s*;\s*refresh/i) { die "Bad SOA refresh: $line"; }
		    $soarefresh = &parsettl($1);
		    $line = <>; if ($line !~ /^\s+(\S+)\s*;\s*retry/i) { die "Bad SOA retry: $line"; }
		    $soaretry = &parsettl($1);
		    $line = <>; if ($line !~ /^\s+(\S+)\s*;\s*expir/i) { die "Bad SOA expires: $line"; }
		    $soaexpires = &parsettl($1);
		    $line = <>; if ($line !~ /^\s+(\S+)\s*\)\s*;\s*minimum/i) { die "Bad SOA minimum: $line"; }
		    $soaminimum = &parsettl($1);
		} else {
		    die "Bad SOA line: $value\n";
		}
		if (!defined($soattl)) { $soattl = $soaminimum }
		if ($soaprimary !~ /\.$/) { $soaprimary .= '.'.$origin; }
		if ($soaemail !~ /\.$/) { $soaemail .= '.'.$origin; }
		$soaprimary = uc($soaprimary);
		$soaemail = uc($soaemail);
		$value = "$soaprimary $soaemail $soaserial $soarefresh $soaretry $soaexpires $soaminimum";
	    } elsif ($type eq 'NS') {
		$value = uc($value);
		if ($value !~ /\.$/) { $value .= '.'.$origin }
	    } elsif ($type eq 'MX') {
		$value = uc($value);
		if ($value !~ /^(\d+)\s+(\S+)$/) {
			die "Bad syntax for MX record: $value";
		}
		$value = "$1 $2";
		if ($value !~ /\.$/) { $value .= '.'.$origin }
	    } elsif ($type eq 'SRV') {
		$value = uc($value);
		if ($value !~ /\.$/) { $value .= '.'.$origin }
	    } elsif ($type eq 'CNAME') {
		$value = uc($value);
	    } elsif ($type eq 'AAAA') {
		$value = uc($value);
	    }
	} else {
		print "Cannot parse: $line\n";
		exit 1;
	}
	my $typeid = $rrid{$type};
	if (!defined($rrid{$type})) { die "unhandled RR type: $type\n"; }
	$rr{"$label $ttl $type $value"} = 1;
}

foreach my $v (sort keys %rr) {
	print $v."\n";
}
