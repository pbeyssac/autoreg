#!/usr/bin/perl
#
# $Id$
#
# Primitives to access the DNS
#

sub dns_get_type_aa {
    local ($domain, $type, $server) = ($_[0], $_[1], $_[2]);
    local ($isauth) = 0;
    local ($inns) = 0;
    local (@answers);

    $type =~ tr/a-z/A-Z/;
    $domain =~ tr/a-z/A-Z/;

    open(DIG,"$DIGPATH $type +noaa $domain. \@$server 2>/dev/null|");
    while (<DIG>) {
        if (/status: NXDOMAIN/) { $isauth=0; last; }
        if (/status: SERVFAIL/) { $isauth=0; last; }
        if (/;; flags.*aa.*;/) { $isauth=1; }
	if (/^;; ANSWER SECTION:$/) { $inns=1; last; }
	if (/^;; ANSWERS:$/) { $inns=1; last; }
    }

    if (!$isauth) {
      close(DIG);
      return "Cannot resolve";
    }

    while (<DIG>) {
	if (/^;;/) { last; }

        if (/\s+$type\s+(.*)$/) {  
	    local ($this) = $1;
    	    close(DIG);
	    $this =~ tr/a-z/A-Z/;
	    push(@answers, $this);
	}
    }
    close(DIG);
    return ("", sort @answers);
}

sub dns_get_type {
    local ($domain, $type, $server) = ($_[0], $_[1], $_[2]);
    local ($isauth) = 1;
    local (@answers);

    $type =~ tr/a-z/A-Z/;
    $domain =~ tr/a-z/A-Z/;

    if ($server) {
	open(DIG,"$DIGPATH $type $domain. \@$server 2>/dev/null|");
    } else {
	open(DIG,"$DIGPATH $type $domain. 2>/dev/null|");
    }
    while (<DIG>) {
        if (/status: NXDOMAIN/) { $isauth=0; last; }
        if (/status: SERVFAIL/) { $isauth=0; last; }
	if (/^;; ANSWER SECTION:$/) { last; }
	if (/^;; ANSWERS:$/) { last; }
    }

    if (!$isauth) {
      close(DIG);
      return "Cannot resolve";
    }

    while (<DIG>) {
	if (/^;;/) { last; }

        if (/\s+$type\s+(.*)$/) {  
	    local ($this) = $1;
    	    close(DIG);
	    $this =~ tr/a-z/A-Z/;
	    push(@answers, $this);
	}
    }
    close(DIG);
    return ("", sort @answers);
}

1;
