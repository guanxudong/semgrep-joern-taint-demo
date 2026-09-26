package MyApp;
use Mojo::Base 'Mojolicious';

sub startup {
    my ($self) = @_;
    my $r = $self->routes;

    $r->get('/users/search')->to('users#search');
    $r->get('/users/search_prepared')->to('users#search_prepared');
    $r->get('/users/lookup')->to('users#lookup');
    $r->get('/users/me/#id')->to('users#get_own_profile');
    $r->get('/users/#id')->to('users#get_user');

    $r->get('/tools/ping')->to('tools#ping');
    $r->get('/tools/diagnose')->to('tools#diagnose');
    $r->post('/tools/calc')->to('tools#calc');

    $r->get('/files/download')->to('files#download');
    $r->get('/files/download_listed')->to('files#download_listed');

    $r->post('/xml/parse')->to('xml#parse');
    $r->post('/xml/parse_basic')->to('xml#parse_basic');

    $r->get('/render/hello')->to('render#hello');
    $r->get('/render/preview')->to('render#preview');

    $r->post('/profile/update')->to('profile#update_profile');
    $r->post('/profile/import')->to('profile#import_profile');

    $r->post('/orders/transfer')->to('orders#transfer');
    $r->post('/orders/coupon')->to('orders#coupon');
    $r->post('/orders/withdraw')->to('orders#withdraw');
    $r->post('/orders/withdraw_locked')->to('orders#withdraw_locked');

    $r->get('/admin/users')->to('admin#list_all_users');
    $r->delete('/admin/users/#id')->to('admin#delete_user');

    $r->post('/auth/login')->to('auth#login');
    $r->post('/auth/reset')->to('auth#request_reset');
}

1;
