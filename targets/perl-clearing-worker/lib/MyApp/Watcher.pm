package MyApp::Watcher;
use strict;
use warnings;

use File::Spec;

my @WATCHERS;

sub watch {
    my ($directory, $handler) = @_;
    push @WATCHERS, [ $directory, $handler ];
}

sub scan_once {
    for my $entry (@WATCHERS) {
        my ($directory, $handler) = @$entry;
        next unless -d $directory;
        opendir(my $dh, $directory) or next;
        for my $name (sort readdir($dh)) {
            next if $name =~ /^\./;
            $handler->({ path => File::Spec->catfile($directory, $name), name => $name });
        }
        closedir($dh);
    }
}

1;
