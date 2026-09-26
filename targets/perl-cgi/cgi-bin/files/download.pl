#!/usr/bin/perl
# Download an uploaded file.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::FileService;

sub run {
    my $q       = CGI->new;
    my $name    = $q->param('name') // '';
    my $svc     = MyApp::Service::FileService->new;
    my $content = $svc->read_user_file($name);
    print $q->header('text/plain');
    print $content;
}

run();
