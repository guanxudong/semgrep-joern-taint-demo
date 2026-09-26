#!/usr/bin/perl
# Show the caller's own account.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::Service::UserService;

sub run {
    my $q            = CGI->new;
    my $id           = $q->param('id') // '';
    my $session_user = $q->http('X-User-Id') // '-1';
    print $q->header('text/plain');
    if ($session_user ne $id) {
        print "forbidden\n";
        return;
    }
    my $svc  = MyApp::Service::UserService->new;
    my $rows = $svc->find_by_id_prepared($id);
    for my $row (@$rows) {
        print "$row->[0]: $row->[1] ($row->[2]) role=$row->[3]\n";
    }
}

run();
