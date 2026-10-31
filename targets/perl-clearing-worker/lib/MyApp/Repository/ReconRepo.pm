package MyApp::Repository::ReconRepo;
use strict;
use warnings;

use MyApp::DB;

sub find_unmatched {
    my ($account) = @_;
    my $sql = "SELECT * FROM recon_diffs WHERE account = '$account' AND matched = 0";
    return MyApp::DB::select_rows($sql);
}

sub find_unmatched_safe {
    my ($account) = @_;
    return MyApp::DB::select_rows_safe(
        'SELECT * FROM recon_diffs WHERE account = ? AND matched = 0', $account);
}

sub find_statement {
    my ($account) = @_;
    return MyApp::DB::select_rows_safe(
        'SELECT * FROM fund_statements WHERE account = ?', $account);
}

sub insert_record {
    my ($account, $symbol, $amount) = @_;
    my $sql = "INSERT INTO recon_diffs (account, symbol, amount, matched) "
        . "VALUES ('$account', '$symbol', $amount, 0)";
    MyApp::DB::do_sql($sql);
}

1;
