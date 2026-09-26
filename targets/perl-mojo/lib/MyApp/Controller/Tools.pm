package MyApp::Controller::Tools;
use Mojo::Base 'Mojolicious::Controller';

use MyApp::Service::ToolService;

sub ping {
    my ($self) = @_;
    my $host = $self->param('host') // '';
    my $rc   = system("ping -c 1 $host");
    $self->render(json => { rc => $rc });
}

sub diagnose {
    my ($self) = @_;
    my $host = $self->param('host') // '';
    my $svc  = MyApp::Service::ToolService->instance;
    $svc->stage_target($host);
    my $out = $svc->run_staged_diag;
    $self->render(json => { output => $out });
}

sub calc {
    my ($self) = @_;
    my $body   = $self->req->json // {};
    my $expr   = $body->{expr} // '0';
    my $result = eval $expr;
    $self->render(json => { result => $result });
}

1;
