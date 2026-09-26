package MyApp::Controller::Admin;
use Mojo::Base 'Mojolicious::Controller';

use MyApp::DB;

sub list_all_users {
    my ($self) = @_;
    my $rows = MyApp::DB::query('SELECT id, username, email, role FROM users');
    $self->render(json => $rows);
}

sub delete_user {
    my ($self) = @_;
    my $id = $self->param('id');
    MyApp::DB::execute("DELETE FROM users WHERE id = $id");
    $self->render(json => { deleted => $id });
}

1;
