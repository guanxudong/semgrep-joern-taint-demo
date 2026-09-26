package MyApp::Controller::Orders;
use Mojo::Base 'Mojolicious::Controller';

use MyApp::Service::OrderService;

sub transfer {
    my ($self) = @_;
    my $body    = $self->req->json // {};
    my $balance = MyApp::Service::OrderService::transfer(
        $body->{src}, $body->{dst}, 0 + ($body->{amount} // 0));
    $self->render(json => { balance => $balance });
}

sub coupon {
    my ($self) = @_;
    my $body = $self->req->json // {};
    my $ok   = MyApp::Service::OrderService::apply_coupon($body->{user}, $body->{coupon});
    $self->render(json => { applied => $ok });
}

sub withdraw {
    my ($self) = @_;
    my $body = $self->req->json // {};
    my $ok   = MyApp::Service::OrderService::withdraw($body->{user}, 0 + ($body->{amount} // 0));
    $self->render(json => { ok => $ok });
}

sub withdraw_locked {
    my ($self) = @_;
    my $body = $self->req->json // {};
    my $ok   = MyApp::Service::OrderService::withdraw_locked($body->{user}, 0 + ($body->{amount} // 0));
    $self->render(json => { ok => $ok });
}

1;
