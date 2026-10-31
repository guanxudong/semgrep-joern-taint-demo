package MyApp::Service::ArchiveService;
use strict;
use warnings;

use File::Spec;
use MyApp::Config;

sub import_attachment {
    my ($name) = @_;
    my $path = File::Spec->catfile(MyApp::Config::archive_dir(), $name);
    open(my $fh, '<', $path) or return undef;
    local $/;
    my $data = <$fh>;
    close($fh);
    return $data;
}

sub import_attachment_safe {
    my ($name) = @_;
    die "illegal attachment name" unless $name =~ /\A[A-Za-z0-9_.-]+\z/;
    my $path = File::Spec->catfile(MyApp::Config::archive_dir(), $name);
    open(my $fh, '<', $path) or return undef;
    local $/;
    my $data = <$fh>;
    close($fh);
    return $data;
}

sub notify_ops {
    my ($title) = @_;
    system("pagerduty-send '" . $title . "'");
}

sub new {
    my ($class) = @_;
    return bless { _pending_label => undef }, $class;
}

sub stage_alert {
    my ($self, $label) = @_;
    $self->{_pending_label} = $label;
}

sub send_staged_alert {
    my ($self) = @_;
    return unless defined $self->{_pending_label};
    system("mail-alert " . $self->{_pending_label});
    $self->{_pending_label} = undef;
}

my $SINGLETON = __PACKAGE__->new;

sub archive_svc { $SINGLETON }

1;
