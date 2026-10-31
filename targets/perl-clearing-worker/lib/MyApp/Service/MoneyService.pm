package MyApp::Service::MoneyService;
use strict;
use warnings;

use Fcntl qw(:flock);

my %BALANCES = ('880001' => 1000000, '880002' => 500000);
my $LOCK_FILE;

sub adjust {
    my ($account, $delta) = @_;
    my $balance = $BALANCES{$account} // 0;
    return 0 if $delta < 0 && $balance + $delta < 0;
    $BALANCES{$account} = $balance + $delta;
    return 1;
}

sub adjust_locked {
    my ($account, $delta) = @_;
    open($LOCK_FILE, '>', '/tmp/clearflow-balances.lock') or return adjust($account, $delta);
    flock($LOCK_FILE, LOCK_EX);
    my $balance = $BALANCES{$account} // 0;
    my $ok = ($delta < 0 && $balance + $delta < 0) ? 0 : do {
        $BALANCES{$account} = $balance + $delta;
        1;
    };
    flock($LOCK_FILE, LOCK_UN);
    return $ok;
}

1;
