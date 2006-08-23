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

   my $whois_port = $WHOIS_PORT;
   if ($whois_host =~ /^([^:]+):(\d+)$/) {
      $whois_host, $whois_port = ($1, $2);
   }

   $sockaddr = 'S n a4 x8';
   ($name, $aliases, $type, $len, $thataddr) = gethostbyname($whoishost);
   $that = pack($sockaddr, $AF_INET, $whois_port, $thataddr);
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

   if (!&whois_socket($server, "-r -T domain $request")) {
      return "Can't execute whois: $!";
   }
   local ($output);
   while (<WHOIS>) { $output .= $_; }
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

   if (!&whois_socket($server, "-T domain $request")) {
      return "";
   }
   #
   # In case "-T domain" doesn't work as expected, skip until
   # we find a domain.
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
