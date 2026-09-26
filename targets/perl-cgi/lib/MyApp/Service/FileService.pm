package MyApp::Service::FileService;
# File retrieval logic.
use strict;
use warnings;
use MyApp::Config;

my %ALLOWED_FILES = map { $_ => 1 } qw(readme.txt help.txt);

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

# Concatenates the given name into a filesystem path.
sub read_user_file {
    my ($self, $name) = @_;
    my $path = MyApp::Config->UPLOAD_DIR . '/' . $name;
    open(my $fh, "<$path") or die "cannot read $path: $!";
    local $/;
    my $content = <$fh>;
    close($fh);
    return $content;
}

sub read_whitelisted {
    my ($self, $name) = @_;
    die "file not allowed" unless $ALLOWED_FILES{$name};
    my $path = MyApp::Config->UPLOAD_DIR . '/' . $name;
    open(my $fh, '<', $path) or die "cannot read $path: $!";
    local $/;
    my $content = <$fh>;
    close($fh);
    return $content;
}

1;
