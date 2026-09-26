#!/usr/bin/perl
# Balance transfer action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::OrderService;

sub run {
    my $q      = CGI->new;
    my $src    = $q->param('src') // '';
    my $dst    = $q->param('dst') // '';
    my $amount = ($q->param('amount') // 0) + 0;
    my $svc    = MyApp::Service::OrderService->new;
    my $balance = $svc->transfer($src, $dst, $amount);
    print $q->header('text/plain');
    print "balance=$balance\n";
}

run();
