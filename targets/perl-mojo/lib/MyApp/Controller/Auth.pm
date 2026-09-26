package MyApp::Controller::Auth;
use Mojo::Base 'Mojolicious::Controller';

use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(hmac_sha256);
use JSON::PP ();
use MIME::Base64 qw(encode_base64);

use MyApp::Config;

sub _b64url {
    my ($data) = @_;
    my $b64 = encode_base64($data, '');
    $b64 =~ tr{+/=}{-_}d;
    return $b64;
}

sub _sign_token {
    my ($claims) = @_;
    my $json    = JSON::PP->new->canonical;
    my $header  = _b64url($json->encode({ alg => 'HS256', typ => 'JWT' }));
    my $payload = _b64url($json->encode($claims));
    my $sig     = _b64url(hmac_sha256("$header.$payload", MyApp::Config::JWT_SECRET));
    return "$header.$payload.$sig";
}

sub login {
    my ($self) = @_;
    my $body     = $self->req->json // {};
    my $username = $body->{username} // '';
    my $token    = _sign_token({ 'sub' => $username, role => 'user' });
    $self->render(json => { token => $token });
}

sub request_reset {
    my ($self) = @_;
    my $body     = $self->req->json // {};
    my $username = $body->{username} // '';
    my $token    = substr(md5_hex($username), 0, 8);
    $self->render(json => { reset_token => $token });
}

1;
