#!/usr/bin/perl
#
# $Id$
#
# Assign handles to all contacts without one
# Use as a filter from stdin to stdout, handles RIPE-db internal format.
# (to be used as a RIPE-db file, should be reindexed with cleandb
# afterwards, then chown'd)
#
my $state = 0;
my %h;

sub mkinitials ()
{
    my $name = shift;
    #print "Person '$name' ";
    my $h = "";
    for (my $i=0; $i<3; $i++) {
	if ($name =~ /^([a-zA-Z])/) {
	    $h .= uc($1);
	}
	if ($name =~ /^\S+\s+(.*)/) {
	    $name = $1; 
	    next
	}
	last
    }
    #print "=> $h\n";
    return $h;
}

sub mkh ()
{
    my $name = shift;
    my $i = &mkinitials($name);
    my $n = 1;
    while (defined($h{"$i$n-FREE"})) {
	$n++;
    }
    #print "$name => $i$n\n";
    $h{"$i$n-FREE"}=1;
    return "$i$n-FREE";
}

while (<STDIN>) {
    if ($state == 0 && /^\s*#/) { next }
    if (/^$/) { $state=0; next }
    if ($state == 0 && /^\*pn:/) { $state=1; next }
    if ($state == 1 && /^\*nh:\s*(\S+)/) { $state=2; $h{uc($1)}=1; next }
    if ($state == 1 && /^\*..:/) { $state=2; next }
}

#foreach my $i (sort keys %h) {
#	print $i."\n";
#}

seek STDIN, 0, 0;
my $p;
while (<STDIN>) {
    if ($state == 0 && /^\s*#/) { print; next }
    if (/^$/) { $state=0; print; next }
    if ($state == 0 && /^\*pn:\s*(.*\S)\s*$/) {
	$p=$1;
	$state=1; print; next
    }
    if ($state == 1 && /^\*nh:/) { $state=2; print; next }
    if ($state == 1 && /^\*..:/) {
	$state=2;
	print "*nh: ".&mkh($p)."\n";
	print; next
    }
    print;
}
