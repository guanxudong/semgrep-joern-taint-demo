#!/usr/bin/perl
# Show a user account by id.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::UserService;

sub run {
    my $q    = CGI->new;
    my $id   = $q->param('id') // '';
    my $svc  = MyApp::Service::UserService->new;
    my $rows = $svc->find_by_id($id);
    print $q->header('text/html');
    print "<ul>\n";
    for my $row (@$rows) {
        print "<li>$row->[0]: $row->[1] ($row->[2]) role=$row->[3]</li>\n";
    }
    print "</ul>\n";
}

run();
