#!/usr/bin/perl
# Balance withdrawal action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::OrderService;

sub run {
    my $q      = CGI->new;
    my $user   = $q->param('user') // '';
    my $amount = ($q->param('amount') // 0) + 0;
    my $svc    = MyApp::Service::OrderService->new;
    my $ok     = $svc->withdraw_locked($user, $amount);
    print $q->header('text/plain');
    print "ok=$ok\n";
}

run();
