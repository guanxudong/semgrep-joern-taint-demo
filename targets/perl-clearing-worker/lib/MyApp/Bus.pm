package MyApp::Bus;
use strict;
use warnings;

my %HANDLERS;

sub subscribe {
    my ($subject, $handler) = @_;
    push @{ $HANDLERS{$subject} }, $handler;
}

sub publish {
    my ($subject, $envelope) = @_;
    for my $handler (@{ $HANDLERS{$subject} }) {
        $handler->($subject, $envelope);
    }
}

1;
