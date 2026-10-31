package MyApp::Handler::Settlement;
use strict;
use warnings;

use MyApp::Parser;
use MyApp::Service::ArchiveService;
use MyApp::Service::ReconService;

sub on_settlement_file {
    my ($event) = @_;
    open(my $fh, '<', $event->{path}) or return undef;
    local $/;
    my $text = <$fh>;
    close($fh);

    my $header = MyApp::Parser::parse_header($text);
    my ($body) = split /\n\n/, $text, 2;
    my $root = MyApp::Parser::parse_settlement_xml($body);
    my $rows = MyApp::Parser::parse_records($text);

    my $svc = MyApp::Service::ReconService::svc();
    $svc->set_operator($header->{operator_role} // 'clerk');
    if ($svc->{operator_role} eq 'admin') {
        $svc->admin_adjust($rows);
    }
    else {
        $svc->apply_settlement($header->{file_id} // $event->{name}, $rows);
    }
    if (my $attachment = $header->{attachment}) {
        MyApp::Service::ArchiveService::import_attachment($attachment);
    }
    return $root;
}

sub on_settlement_file_safe {
    my ($event) = @_;
    open(my $fh, '<', $event->{path}) or return undef;
    local $/;
    my $text = <$fh>;
    close($fh);

    my $header = MyApp::Parser::parse_header($text);
    my ($body) = split /\n\n/, $text, 2;
    my $root = MyApp::Parser::parse_settlement_xml_safe($body);
    if (my $attachment = $header->{attachment}) {
        MyApp::Service::ArchiveService::import_attachment_safe($attachment);
    }
    return $root;
}

1;
