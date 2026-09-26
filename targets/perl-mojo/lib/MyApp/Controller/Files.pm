package MyApp::Controller::Files;
use Mojo::Base 'Mojolicious::Controller';

use MyApp::Service::FileService;

sub download {
    my ($self) = @_;
    my $name    = $self->param('name') // '';
    my $content = MyApp::Service::FileService::read_file($name);
    $self->render(json => { content => $content });
}

sub download_listed {
    my ($self) = @_;
    my $name    = $self->param('name') // '';
    my $content = eval { MyApp::Service::FileService::read_listed($name) };
    if (!defined $content) {
        return $self->render(json => { error => 'file not allowed' }, status => 400);
    }
    $self->render(json => { content => $content });
}

1;
