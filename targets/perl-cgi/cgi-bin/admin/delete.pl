#!/usr/bin/perl
# Admin: delete a user account.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::DB;

sub run {
    my $q  = CGI->new;
    my $id = $q->param('id') // '';
    MyApp::DB->execute("DELETE FROM users WHERE id = $id");
    print $q->header('text/plain');
    print "deleted=$id\n";
}

run();
