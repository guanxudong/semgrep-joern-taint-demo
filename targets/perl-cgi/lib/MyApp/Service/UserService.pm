package MyApp::Service::UserService;
# User lookup logic.
use strict;
use warnings;
use MyApp::DB;

sub new {
    my ($class) = @_;
    return bless { _pending_name => '' }, $class;
}

# Store the given name in a field.
sub stage_name {
    my ($self, $name) = @_;
    $self->{_pending_name} = $name;
}

# Read the staged field and run the lookup.
sub find_staged {
    my ($self) = @_;
    my $sql = "SELECT id, username, email FROM users WHERE username = '" . $self->{_pending_name} . "'";
    return MyApp::DB->query($sql);
}

sub find_by_id {
    my ($self, $user_id) = @_;
    my $sql = "SELECT id, username, email, role FROM users WHERE id = $user_id";
    return MyApp::DB->query($sql);
}

sub find_by_id_prepared {
    my ($self, $user_id) = @_;
    return MyApp::DB->query_prepared(
        'SELECT id, username, email, role FROM users WHERE id = ?', $user_id);
}

1;
