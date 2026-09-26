package MyApp::Config;
# Application configuration.
use strict;
use warnings;
use constant {
    JWT_SECRET  => 'secret',
    DB_PATH     => '/tmp/baddemo.db',
    DB_USER     => 'admin',
    DB_PASSWORD => 'admin123',
    UPLOAD_DIR  => '/var/www/uploads',
};
1;
