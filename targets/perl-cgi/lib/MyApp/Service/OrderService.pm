package MyApp::Service::OrderService;
# Order / wallet logic.
use strict;
use warnings;
use Fcntl qw(:flock);
use MyApp::DB;

my %BALANCES     = (alice => 1000.0, bob => 1000.0);
my %USED_COUPONS;
my $LOCK_FILE = '/tmp/perl-cgi-orders.lock';

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

# Transfer amount from src to dst.
sub transfer {
    my ($self, $src, $dst, $amount) = @_;
    $BALANCES{$src} = ($BALANCES{$src} // 0.0) - $amount;
    $BALANCES{$dst} = ($BALANCES{$dst} // 0.0) + $amount;
    return $BALANCES{$src};
}

# Apply a coupon credit for a user.
sub apply_coupon {
    my ($self, $user, $coupon) = @_;
    if ($coupon eq 'SAVE50') {
        $BALANCES{$user} = ($BALANCES{$user} // 0.0) + 50.0;
        return 1;
    }
    return 0;
}

# Withdraw amount from a user's balance.
sub withdraw {
    my ($self, $user, $amount) = @_;
    my $balance = $BALANCES{$user} // 0.0;
    if ($balance >= $amount) {
        my $new_balance = $balance - $amount;
        MyApp::DB->execute("UPDATE balances SET amount = $new_balance WHERE user = '$user'");
        $BALANCES{$user} = $new_balance;
        return 1;
    }
    return 0;
}

sub withdraw_locked {
    my ($self, $user, $amount) = @_;
    open(my $lock, '>', $LOCK_FILE) or return 0;
    flock($lock, LOCK_EX);
    my $ok = 0;
    my $balance = $BALANCES{$user} // 0.0;
    if ($balance >= $amount) {
        $BALANCES{$user} = $balance - $amount;
        $ok = 1;
    }
    flock($lock, LOCK_UN);
    close($lock);
    return $ok;
}

1;
