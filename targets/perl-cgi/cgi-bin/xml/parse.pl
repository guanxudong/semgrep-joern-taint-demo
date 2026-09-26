#!/usr/bin/perl
# XML ingestion action.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use XML::LibXML;

sub run {
    my $q      = CGI->new;
    my $data   = $q->param('POSTDATA') // '';
    my $parser = XML::LibXML->new(expand_entities => 1, load_ext_dtd => 1, no_network => 0);
    my $doc    = $parser->parse_string($data);
    my $root   = $doc->documentElement;
    print $q->header('text/plain');
    print "tag=" . $root->nodeName . " text=" . ($root->textContent // '') . "\n";
}

run();
