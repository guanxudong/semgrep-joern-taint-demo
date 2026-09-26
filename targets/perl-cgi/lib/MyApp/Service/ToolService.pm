package MyApp::Service::ToolService;
# Diagnostic command helpers.
use strict;
use warnings;

sub new {
    my ($class) = @_;
    return bless { _target => '' }, $class;
}

sub stage_target {
    my ($self, $host) = @_;
    $self->{_target} = $host;
}

sub run_staged_diag {
    my ($self) = @_;
    my $cmd = "ping -c 1 " . $self->{_target};
    return system($cmd);
}

1;
