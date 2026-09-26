#!/usr/bin/perl
# Profile update action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;

my %USERS = (alice => { username => 'alice', email => '', role => 'user' });

sub run {
    my $q        = CGI->new;
    my $username = $q->param('username') // '';
    my $user     = $USERS{$username}
        //= { username => $username, email => '', role => 'user' };
    for my $key ($q->param) {
        $user->{$key} = $q->param($key);
    }
    print $q->header('text/plain');
    print "username=$user->{username} email=$user->{email} role=$user->{role}\n";
}

run();
