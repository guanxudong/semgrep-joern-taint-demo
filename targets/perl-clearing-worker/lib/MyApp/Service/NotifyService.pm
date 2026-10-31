package MyApp::Service::NotifyService;
use strict;
use warnings;

sub render_result_email {
    my ($account, $rows) = @_;
    my $html = "<h2>Recon result for $account</h2>\n<table>\n";
    for my $row (@$rows) {
        $html .= "<tr><td>" . $row->{symbol} . "</td><td>" . $row->{diff} . "</td></tr>\n";
    }
    $html .= "</table>\n";
    return $html;
}

sub render_notice {
    my ($template, $ctx) = @_;
    my $compiled = $template;
    $compiled =~ s/\[%\s*(.+?)\s*%\]/'"'.do{ $ctx->{$1} }.'"'/gee;
    return $compiled;
}

1;
