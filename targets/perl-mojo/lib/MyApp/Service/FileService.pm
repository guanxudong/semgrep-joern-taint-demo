package MyApp::Service::FileService;
use strict;
use warnings;

use MyApp::Config;

my %LISTED_FILES = map { $_ => 1 } ('readme.txt', 'help.txt');

sub read_file {
    my ($name) = @_;
    my $path = MyApp::Config::UPLOAD_DIR . '/' . $name;
    open(my $fh, "<$path") or die "cannot open $path: $!";
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
}

sub read_listed {
    my ($name) = @_;
    die "file not allowed" unless $LISTED_FILES{$name};
    my $path = MyApp::Config::UPLOAD_DIR . '/' . $name;
    open(my $fh, '<', $path) or die "cannot open $path: $!";
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
}

1;
