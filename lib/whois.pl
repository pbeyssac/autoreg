#!/usr/bin/perl
#
# $Id$
#

$WHOIS="/usr/bin/whois";

sub whois_domain {
   local ($server, $request) = ($_[0], $_[1]);
   $server =~ s/["';&]//g;
   $request =~ s/["';&]//g;

   if (!open(WHOIS, "$WHOIS -h \"$server\" \" -r -T domain $request\"|")) {
      return "Can't execute whois: $!";
   }
   local ($output);
   while (<WHOIS>) { $output .= $_; }
   close(WHOIS);
   return ("", $output);
}

sub whois_html {
   local ($server, $request) = ($_[0], $_[1]);
   $server =~ s/["';&]//g;
   $request =~ s/["';&]//g;

   if (!open(WHOIS, "$WHOIS -h \"$server\" \"$request\"|")) {
      print "<STRONG>Can't execute whois: $!</STRONG>\n";
      return;
   }
   print "<TT>whois -h $server $request</TT>\n";
   print "<PRE>\n";
   while (<WHOIS>) {
      s/</&lt;/g;
      s/>/&gt;/g;
      print;
   }
   print "</PRE>\n";
   close(WHOIS);
}

1;
