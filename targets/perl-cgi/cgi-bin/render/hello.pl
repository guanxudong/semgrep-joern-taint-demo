#!/usr/bin/perl
# Greeting page.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;

sub run {
    my $q    = CGI->new;
    my $name = $q->param('name') // '';
    print $q->header('text/html');
    print "<h1>Hello " . $name . "</h1>";
}

run();
