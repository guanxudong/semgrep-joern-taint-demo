#!/usr/bin/perl
# Ping a host.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;

sub run {
    my $q    = CGI->new;
    my $host = $q->param('host') // '';
    my $rc   = system("ping -c 1 " . $host);
    print $q->header('text/plain');
    print "rc=$rc\n";
}

run();
