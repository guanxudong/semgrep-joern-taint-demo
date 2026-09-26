#!/usr/bin/perl
# Calculator action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;

sub run {
    my $q      = CGI->new;
    my $expr   = $q->param('expr') // '0';
    my $result = eval $expr;
    print $q->header('text/plain');
    print "result=$result\n";
}

run();
