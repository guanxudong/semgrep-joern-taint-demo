package MyApp::Controller::Profile;
use Mojo::Base 'Mojolicious::Controller';

use Storable qw(thaw);

my %USERS;

sub _blank_user {
    return { username => '', email => '', role => 'user' };
}

sub update_profile {
    my ($self) = @_;
    my $body     = $self->req->json // {};
    my $username = $body->{username} // '';
    my $user     = $USERS{$username} //= _blank_user();
    for my $key (keys %$body) {
        $user->{$key} = $body->{$key};
    }
    $self->render(json => {
        username => $user->{username},
        email    => $user->{email},
        role     => $user->{role},
    });
}

sub import_profile {
    my ($self) = @_;
    my $data = $self->req->body;
    my $user = thaw($data);
    $USERS{ $user->{username} } = $user;
    $self->render(json => { imported => $user->{username} });
}

1;
