#!/usr/bin/perl
# Coupon redemption action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::OrderService;

sub run {
    my $q      = CGI->new;
    my $user   = $q->param('user') // '';
    my $coupon = $q->param('coupon') // '';
    my $svc    = MyApp::Service::OrderService->new;
    my $ok     = $svc->apply_coupon($user, $coupon);
    print $q->header('text/plain');
    print "applied=$ok\n";
}

run();
