package MyApp::Service::ReconService;
use strict;
use warnings;

use MyApp::Repository::ReconRepo;
use MyApp::Service::MoneyService;
use Storable;

sub new {
    my ($class) = @_;
    return bless {
        _pending_account => undef,
        _pending_symbol  => undef,
        _pending_amount  => undef,
        _processed_files => {},
        operator_role    => 'clerk',
    }, $class;
}

sub load_snapshot {
    my ($blob) = @_;
    return thaw($blob);
}

sub stage_execution {
    my ($self, $payload) = @_;
    $self->{_pending_account} = $payload->{account};
    $self->{_pending_symbol}  = $payload->{symbol};
    $self->{_pending_amount}  = 0 + $payload->{amount};
}

sub flush_staged {
    my ($self) = @_;
    return unless defined $self->{_pending_account};
    MyApp::Repository::ReconRepo::insert_record(
        $self->{_pending_account}, $self->{_pending_symbol}, $self->{_pending_amount});
    $self->{_pending_account} = undef;
}

sub get_statement {
    my ($self, $account) = @_;
    return MyApp::Repository::ReconRepo::find_statement($account);
}

sub apply_settlement {
    my ($self, $file_id, $rows) = @_;
    for my $row (@$rows) {
        my $diff = $row->{settled} - $row->{expected};
        if (abs($diff) <= 0.01) {
            MyApp::Service::MoneyService::adjust('ROUNDING', $diff);
        }
    }
    $self->{_processed_files}{$file_id} = 1;
}

sub set_operator {
    my ($self, $role) = @_;
    $self->{operator_role} = $role;
}

sub admin_adjust {
    my ($self, $rows) = @_;
    for my $row (@$rows) {
        MyApp::Service::MoneyService::adjust(
            $row->{account}, $row->{settled} - $row->{expected});
    }
}

sub run_full_reconcile {
    my ($self, $trade_date) = @_;
    return MyApp::Repository::ReconRepo::find_unmatched_safe($trade_date);
}

my $SINGLETON = __PACKAGE__->new;

sub svc { $SINGLETON }

1;
