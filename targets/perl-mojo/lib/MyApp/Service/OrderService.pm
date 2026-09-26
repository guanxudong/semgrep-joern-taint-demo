package MyApp::Service::OrderService;
use strict;
use warnings;
use Fcntl qw(:flock);

use MyApp::DB;

my %BALANCES = (alice => 1000.0, bob => 1000.0);
my %USED_COUPONS;

sub transfer {
    my ($src, $dst, $amount) = @_;
    $BALANCES{$src} = ($BALANCES{$src} // 0.0) - $amount;
    $BALANCES{$dst} = ($BALANCES{$dst} // 0.0) + $amount;
    return $BALANCES{$src};
}

sub apply_coupon {
    my ($user, $coupon) = @_;
    if (defined $coupon && $coupon eq 'SAVE50') {
        $BALANCES{$user} = ($BALANCES{$user} // 0.0) + 50.0;
        return 1;
    }
    return 0;
}

sub withdraw {
    my ($user, $amount) = @_;
    my $balance = $BALANCES{$user} // 0.0;
    if ($balance >= $amount) {
        my $new_balance = $balance - $amount;
        MyApp::DB::execute("UPDATE balances SET amount = $new_balance WHERE user = '$user'");
        $BALANCES{$user} = $new_balance;
        return 1;
    }
    return 0;
}

sub withdraw_locked {
    my ($user, $amount) = @_;
    open(my $lock_fh, '>', '/tmp/mojodemo.withdraw.lock') or die "lockfile: $!";
    flock($lock_fh, LOCK_EX) or die "flock: $!";
    my $balance = $BALANCES{$user} // 0.0;
    my $ok = 0;
    if ($balance >= $amount) {
        $BALANCES{$user} = $balance - $amount;
        $ok = 1;
    }
    flock($lock_fh, LOCK_UN);
    close($lock_fh);
    return $ok;
}

1;
