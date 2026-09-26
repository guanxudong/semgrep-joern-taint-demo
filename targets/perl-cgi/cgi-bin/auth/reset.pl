#!/usr/bin/perl
# Password reset request action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use Digest::MD5 qw(md5_hex);

sub run {
    my $q        = CGI->new;
    my $username = $q->param('username') // '';
    my $token    = substr(md5_hex($username), 0, 8);
    print $q->header('text/plain');
    print "reset_token=$token\n";
}

run();
