package MyApp::Controller::Users;
use Mojo::Base 'Mojolicious::Controller';

use MyApp::DB;
use MyApp::Service::UserService;

sub search {
    my ($self) = @_;
    my $q    = $self->param('q') // '';
    my $rows = MyApp::DB::query("SELECT id, username FROM users WHERE username LIKE '%$q%'");
    $self->render(json => $rows);
}

sub search_prepared {
    my ($self) = @_;
    my $q    = $self->param('q') // '';
    my $rows = MyApp::DB::query_prepared(
        'SELECT id, username FROM users WHERE username LIKE ?', '%' . $q . '%');
    $self->render(json => $rows);
}

sub lookup {
    my ($self) = @_;
    my $name = $self->param('name') // '';
    my $svc  = MyApp::Service::UserService->instance;
    $svc->stage_name($name);
    my $rows = $svc->find_staged;
    $self->render(json => $rows);
}

sub get_user {
    my ($self) = @_;
    my $id   = $self->param('id');
    my $rows = MyApp::Service::UserService->instance->find_by_id($id);
    $self->render(json => $rows);
}

sub get_own_profile {
    my ($self) = @_;
    my $id           = $self->param('id');
    my $session_user = $self->req->headers->header('X-User-Id') // '-1';
    if ($session_user != $id) {
        return $self->render(json => { error => 'forbidden' }, status => 403);
    }
    my $rows = MyApp::Service::UserService->instance->find_by_id_prepared($id);
    $self->render(json => $rows);
}

1;
