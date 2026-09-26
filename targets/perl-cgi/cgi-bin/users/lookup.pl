#!/usr/bin/perl
# User lookup action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::UserService;

sub run {
    my $q    = CGI->new;
    my $name = $q->param('name') // '';
    my $svc  = MyApp::Service::UserService->new;
    $svc->stage_name($name);
    my $rows = $svc->find_staged;
    print $q->header('text/html');
    print "<ul>\n";
    for my $row (@$rows) {
        print "<li>$row->[0]: $row->[1] ($row->[2])</li>\n";
    }
    print "</ul>\n";
}

run();
