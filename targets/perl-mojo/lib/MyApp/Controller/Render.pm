package MyApp::Controller::Render;
use Mojo::Base 'Mojolicious::Controller';

use Template;

sub hello {
    my ($self) = @_;
    my $name = $self->param('name') // '';
    $self->render(text => '<h1>Hello ' . $name . '</h1>');
}

sub preview {
    my ($self) = @_;
    my $tpl = $self->param('tpl') // '';
    my $tt  = Template->new;
    my $out = '';
    $tt->process(\$tpl, {}, \$out);
    $self->render(text => $out);
}

1;
