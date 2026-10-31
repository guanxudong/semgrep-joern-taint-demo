package MyApp::Service::RuleEngine;
use strict;
use warnings;

sub evaluate {
    my ($expr, $data) = @_;
    return eval $expr;
}

1;
