#!/usr/bin/perl
# User search action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::DB;

sub run {
    my $q    = CGI->new;
    my $term = $q->param('q') // '';
    my $rows = MyApp::DB->query_prepared(
        'SELECT id, username FROM users WHERE username LIKE ?', '%' . $term . '%');
    print $q->header('text/html');
    print "<ul>\n";
    for my $row (@$rows) {
        print "<li>$row->[0]: $row->[1]</li>\n";
    }
    print "</ul>\n";
}

run();
