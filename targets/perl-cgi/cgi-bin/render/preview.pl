#!/usr/bin/perl
# Template preview action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use Template;

sub run {
    my $q   = CGI->new;
    my $tpl = $q->param('tpl') // '';
    my $tt  = Template->new;
    my $out = '';
    $tt->process(\$tpl, {}, \$out);
    print $q->header('text/html');
    print $out;
}

run();
