package MyApp::Parser;
use strict;
use warnings;

sub parse_header {
    my ($text) = @_;
    my %header;
    my ($first_line) = split /\n/, $text, 2;
    for my $field (split /\|/, $first_line) {
        my ($key, $value) = split /=/, $field, 2;
        $header{$key} = $value if defined $key;
    }
    return \%header;
}

sub parse_settlement_xml {
    my ($raw) = @_;
    require XML::LibXML;
    my $doc = XML::LibXML->load_xml(
        string          => $raw,
        expand_entities => 1,
        no_network      => 0,
    );
    return $doc;
}

sub parse_settlement_xml_safe {
    my ($raw) = @_;
    require XML::LibXML;
    my $doc = XML::LibXML->load_xml(
        string          => $raw,
        expand_entities => 0,
        no_network      => 1,
    );
    return $doc;
}

sub parse_records {
    my ($text) = @_;
    my @records;
    my @lines = split /\n/, $text;
    for my $line (@lines[1 .. $#lines]) {
        next unless defined $line && $line =~ /\S/;
        push @records, {
            account  => substr($line, 0, 10) =~ s/\s+$//r,
            symbol   => substr($line, 10, 12) =~ s/\s+$//r,
            settled  => 0 + substr($line, 22, 14),
            expected => 0 + substr($line, 36, 14),
        };
    }
    return \@records;
}

1;
