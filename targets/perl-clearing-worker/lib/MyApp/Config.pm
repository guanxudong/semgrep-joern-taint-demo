package MyApp::Config;
use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;

my $base = dirname(dirname(dirname(dirname(File::Spec->rel2abs(__FILE__)))));

sub base_dir     { $base }
sub db_path      { File::Spec->catfile($base, 'data', 'clearflow.db') }
sub inbox_dir    { File::Spec->catdir($base, 'drop', 'inbox') }
sub archive_dir  { File::Spec->catdir($base, 'drop', 'archive') }

sub mq_endpoint  { 'rv://bus.clearflow.local:7500' }
sub sftp_host    { 'sftp.csdcc.local' }
sub sftp_user    { 'clearflow' }
sub sftp_password { 'clearflow123' }

sub token_secret { 'clearflow-secret' }
sub tolerance    { 0.01 }

1;
