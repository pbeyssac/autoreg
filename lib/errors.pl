#!/usr/bin/perl
#
# $Id$
#
# Helper functions for error processing
#

sub pr_error {
	printf @_;
	$numerrs++;
}
sub stoperrs {
	select(STDOUT); $| = 1; print ""; $| = 0;
	die sprintf($MSG_NBERR, $numerrs) if $numerrs;
}

1;
