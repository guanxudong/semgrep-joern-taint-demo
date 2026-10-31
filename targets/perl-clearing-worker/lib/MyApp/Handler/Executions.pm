package MyApp::Handler::Executions;
use strict;
use warnings;

use MyApp::Service::MoneyService;
use MyApp::Service::ReconService;

sub on_execution_report {
    my ($subject, $envelope) = @_;
    my $payload = $envelope->{payload};
    my $record = {};
    for my $key (keys %$payload) {
        $record->{$key} = $payload->{$key};
    }
    MyApp::Service::MoneyService::adjust($payload->{account}, 0 + $payload->{amount});
    my $svc = MyApp::Service::ReconService::svc();
    $svc->stage_execution($payload);
    $svc->flush_staged();
}

sub on_execution_report_safe {
    my ($subject, $envelope) = @_;
    my $payload = $envelope->{payload};
    MyApp::Service::MoneyService::adjust_locked($payload->{account}, 0 + $payload->{amount});
}

1;
