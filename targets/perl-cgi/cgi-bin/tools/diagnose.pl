#!/usr/bin/perl
# Run a staged host diagnostic.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::ToolService;

sub run {
    my $q    = CGI->new;
    my $host = $q->param('host') // '';
    my $svc  = MyApp::Service::ToolService->new;
    $svc->stage_target($host);
    my $rc = $svc->run_staged_diag;
    print $q->header('text/plain');
    print "rc=$rc\n";
}

run();
