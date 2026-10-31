package MyApp::Handler::Reconciliation;
use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use MyApp::Config;
use MyApp::Repository::ReconRepo;
use MyApp::Service::NotifyService;
use MyApp::Service::ReconService;
use MyApp::Service::RuleEngine;
use MyApp::Uploader;

sub _token_ok {
    my ($account, $trade_date, $token) = @_;
    my $expected = md5_hex("$account|$trade_date");
    return $token eq $expected;
}

sub on_diff_query {
    my ($subject, $envelope) = @_;
    my $account = $envelope->{payload}{account};
    return MyApp::Repository::ReconRepo::find_unmatched($account);
}

sub on_diff_query_safe {
    my ($subject, $envelope) = @_;
    my $account = $envelope->{payload}{account};
    return MyApp::Repository::ReconRepo::find_unmatched_safe($account);
}

sub on_request {
    my ($subject, $envelope) = @_;
    my $payload  = $envelope->{payload};
    my $headers  = $envelope->{headers} // {};
    return undef unless _token_ok($payload->{account}, $payload->{date}, $headers->{token} // '');
    my $rows = MyApp::Service::ReconService::svc()->get_statement($payload->{account});
    MyApp::Uploader::put(
        host     => MyApp::Config::sftp_host(),
        user     => MyApp::Config::sftp_user(),
        password => MyApp::Config::sftp_password(),
        account  => $payload->{account},
        rows     => $rows,
    );
    return $rows;
}

sub on_request_safe {
    my ($subject, $envelope) = @_;
    my $payload = $envelope->{payload};
    my $headers = $envelope->{headers} // {};
    return undef unless ($headers->{requester} // '') eq $payload->{account};
    return MyApp::Service::ReconService::svc()->get_statement($payload->{account});
}

sub on_alert_rule {
    my ($subject, $envelope) = @_;
    my $expr = $envelope->{payload}{expr};
    return MyApp::Service::RuleEngine::evaluate($expr, $envelope->{payload}{data});
}

sub on_load_snapshot {
    my ($subject, $envelope) = @_;
    return MyApp::Service::ReconService::load_snapshot($envelope->{payload}{blob});
}

sub on_run_batch {
    my ($subject, $envelope) = @_;
    return MyApp::Service::ReconService::svc()->run_full_reconcile($envelope->{payload}{date});
}

sub on_reconcile_done {
    my ($subject, $envelope) = @_;
    return MyApp::Service::NotifyService::render_result_email(
        $envelope->{payload}{account}, $envelope->{payload}{rows});
}

1;
