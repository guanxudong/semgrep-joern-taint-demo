package MyApp::Service::UserService;
use strict;
use warnings;

use MyApp::DB;

my $instance;

sub new {
    my ($class) = @_;
    return bless { _pending_name => '' }, $class;
}

sub instance {
    my ($class) = @_;
    $instance //= $class->new;
}

sub stage_name {
    my ($self, $name) = @_;
    $self->{_pending_name} = $name;
}

sub find_staged {
    my ($self) = @_;
    my $sql = "SELECT id, username, email FROM users WHERE username = '$self->{_pending_name}'";
    return MyApp::DB::query($sql);
}

sub find_by_name {
    my ($self, $name) = @_;
    my $sql = "SELECT id, username, email FROM users WHERE username = '$name'";
    return MyApp::DB::query($sql);
}

sub find_by_id {
    my ($self, $id) = @_;
    my $sql = "SELECT id, username, email, role FROM users WHERE id = $id";
    return MyApp::DB::query($sql);
}

sub find_by_id_prepared {
    my ($self, $id) = @_;
    return MyApp::DB::query_prepared(
        'SELECT id, username, email, role FROM users WHERE id = ?', $id);
}

1;
