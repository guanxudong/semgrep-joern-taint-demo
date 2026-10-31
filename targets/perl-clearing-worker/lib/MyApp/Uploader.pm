package MyApp::Uploader;
use strict;
use warnings;

sub put {
    my (%args) = @_;
    return {
        host => $args{host},
        user => $args{user},
        path => "/out/$args{account}.txt",
        rows => scalar @{ $args{rows} // [] },
    };
}

1;
