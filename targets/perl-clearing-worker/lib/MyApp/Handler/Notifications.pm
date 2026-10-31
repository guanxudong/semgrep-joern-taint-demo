package MyApp::Handler::Notifications;
use strict;
use warnings;

use MyApp::Service::ArchiveService;
use MyApp::Service::NotifyService;

sub on_notify {
    my ($subject, $envelope) = @_;
    my $payload = $envelope->{payload};
    if (defined $payload->{template}) {
        return MyApp::Service::NotifyService::render_notice($payload->{template}, $payload);
    }
    if ($payload->{defer}) {
        my $svc = MyApp::Service::ArchiveService::archive_svc();
        $svc->stage_alert($payload->{title});
        $svc->send_staged_alert();
        return undef;
    }
    MyApp::Service::ArchiveService::notify_ops($payload->{title});
    return undef;
}

1;
