#!/usr/bin/perl
#
# $Id$
#

$WHOIS_PORT = 43;
$AF_INET = 2;
$SOCK_STREAM = 1;

sub whois_socket {
   local ($whoishost, $request) = ($_[0], $_[1]);
   local ($name, $aliases, $type, $len, $thataddr, $sockaddr, $that);

   my $whoisport = $WHOIS_PORT;
   if ($whoishost =~ /^([^:]+):(\d+)$/) {
      $whoishost, $whoisport = ($1, $2);
   }

   $sockaddr = 'S n a4 x8';
   ($name, $aliases, $type, $len, $thataddr) = gethostbyname($whoishost);
   $that = pack($sockaddr, $AF_INET, $whoisport, $thataddr);
   socket(WHOIS, $AF_INET, $SOCK_STREAM, $proto) || return "";
   if (!connect(WHOIS, $that)) {
      close(WHOIS);
      return "";
   }
   select(WHOIS); $| = 1; select(STDOUT);
   print WHOIS "$request\r\n";
   return 1;
}

sub whois_domain {
   local ($server, $request) = ($_[0], $_[1]);
   $server =~ s/["';&]//g;
   $request =~ s/["';&]//g;

   if (!&whois_socket($server, "$request")) {
      return "Can't execute whois: $!";
   }
   local ($output);
   while (<WHOIS>) {
      last if (/^person:/i);
      $output .= $_;
   }
   close(WHOIS);
   return ("", $output);
}

sub whois_html {
   local ($server, $request, $typecount) = ($_[0], $_[1], $_[2]);
   $server =~ s/["';&]//g;
   $request =~ s/["';&]//g;

   if (!&whois_socket($server, $request)) {
      print "<STRONG>Can't execute whois: $!</STRONG>\n";
      return -1;
   }
   my $c = 0;
   print "<TT>\"$request\" at $server</TT>\n";
   print "<PRE>\n";
   while (<WHOIS>) {
      if (defined($typecount) && /^$typecount:/) { $c++ }
      s/&/&amp;/g;
      s/</&lt;/g;
      s/>/&gt;/g;
      print;
   }
   print "</PRE>\n";
   close(WHOIS);
   return $c;
}

sub whois_email {
   local ($server, $request) = ($_[0], $_[1]);
   local (%emails);
   $server =~ s/["';&]//g;
   $request =~ s/["';&]//g;

   if (!&whois_socket($server, "$request")) {
      return "";
   }
   #
   # Skip until we find a domain.
   #
   while (<WHOIS>) {
      last if (/^domain:/i);
   }
   while (<WHOIS>) {
      if (/^e-mail:\s*(.*)$/i) {
	$emails{$1} = 1;
      }
   }
   close(WHOIS);
   return sort keys(%emails);
}

1;
