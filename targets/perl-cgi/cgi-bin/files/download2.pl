#!/usr/bin/perl
# Download an uploaded file.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::FileService;

sub run {
    my $q    = CGI->new;
    my $name = $q->param('name') // '';
    my $svc  = MyApp::Service::FileService->new;
    print $q->header('text/plain');
    my $content = eval { $svc->read_whitelisted($name) };
    if ($@) {
        print "file not allowed\n";
        return;
    }
    print $content;
}

run();
