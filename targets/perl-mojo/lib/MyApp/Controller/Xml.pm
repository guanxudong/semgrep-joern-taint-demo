package MyApp::Controller::Xml;
use Mojo::Base 'Mojolicious::Controller';

use XML::LibXML;

sub parse {
    my ($self) = @_;
    my $data   = $self->req->body;
    my $parser = XML::LibXML->new;
    $parser->expand_entities(1);
    $parser->load_ext_dtd(1);
    my $doc  = $parser->parse_string($data);
    my $root = $doc->documentElement;
    $self->render(json => { tag => $root->nodeName, text => $root->textContent });
}

sub parse_basic {
    my ($self) = @_;
    my $data   = $self->req->body;
    my $parser = XML::LibXML->new;
    $parser->expand_entities(0);
    $parser->load_ext_dtd(0);
    my $doc  = $parser->parse_string($data);
    my $root = $doc->documentElement;
    $self->render(json => { tag => $root->nodeName, text => $root->textContent });
}

1;
