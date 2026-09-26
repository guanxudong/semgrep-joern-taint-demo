#!/usr/bin/perl
# Profile import action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use Storable qw(thaw);

my %PROFILES;

sub run {
    my $q       = CGI->new;
    my $data    = $q->param('POSTDATA') // '';
    my $profile = thaw($data);
    $PROFILES{ $profile->{username} } = $profile;
    print $q->header('text/plain');
    print "imported=$profile->{username}\n";
}

run();
