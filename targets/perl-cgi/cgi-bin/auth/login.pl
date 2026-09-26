#!/usr/bin/perl
# Login action: issues a session token.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA qw(hmac_sha256_base64);
use MyApp::Config;

sub run {
    my $q        = CGI->new;
    my $username = $q->param('username') // '';
    my $password = $q->param('password') // '';
    my $header   = encode_base64url('{"alg":"HS256","typ":"JWT"}');
    my $payload  = encode_base64url('{"sub":"' . $username . '","role":"user"}');
    my $sig      = hmac_sha256_base64("$header.$payload", MyApp::Config->JWT_SECRET);
    $sig =~ s/=+$//;
    print $q->header('text/plain');
    print "token=$header.$payload.$sig\n";
}

run();
