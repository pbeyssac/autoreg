#!/usr/bin/perl
#
# $Id$
#
# Misc. utility functions
#

sub parent_of {
  local ($domain) = @_;
  local ($i) = index($domain, ".");
  if ($i < 0) { 
    return "";
  }
  return substr($domain, $i+1);
}

sub fqdncanon {
	local ($fqdn)=$_[0];
	if ($fqdn =~ /^\.(.*)/)	{ $fqdn = $1 }
	if ($fqdn =~ /\.$/)	{ chop $fqdn }
	$fqdn =~ tr/a-z/A-Z/;
	return $fqdn;
}

# isasubdomain(subdomain, domain)
# Returns :
#	0 if subdomain is not in domain
#	1 if subdomain is not directly under domain
#	2 if subdomain is directly under domain
#
sub isasubdomain {
	local ($sub, $dom)= ($_[0], $_[1]);
	local ($ls)= 0;
	local ($ld)= 0;
	local ($comp);

	$sub = &fqdncanon($sub);
	$dom = &fqdncanon($dom);

	$dom = '.' . $dom;

	$ls = length($sub) - length($dom);
	if ($ls <= 0) {
		return 0;
	}
	$comp = (substr($sub, $ls) eq $dom);
	if ($comp && $ls == index($sub, ".")) { $comp++ }
	return $comp;
}

1;
