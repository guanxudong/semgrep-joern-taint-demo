package MyApp::Service::ToolService;
use strict;
use warnings;

my $instance;

sub new {
    my ($class) = @_;
    return bless { _target => '' }, $class;
}

sub instance {
    my ($class) = @_;
    $instance //= $class->new;
}

sub stage_target {
    my ($self, $host) = @_;
    $self->{_target} = $host;
}

sub run_staged_diag {
    my ($self) = @_;
    my $cmd = "ping -c 1 $self->{_target}";
    my $out = qx($cmd);
    return $out;
}

1;
