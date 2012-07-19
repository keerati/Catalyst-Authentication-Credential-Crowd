use inc::Module::Install 0.65;

name 'Catalyst-Authentication-Credential-Crowd';
all_from 'lib/Catalyst/Authentication/Credential/Crowd.pm';

requires 'Moose';
requires 'Catalyst::Runtime';
requires 'Catalyst::Plugin::Authentication';
requires 'HTTP::Request';
requires 'LWP::UserAgent';
requires 'JSON';

test_requires 'Test::Fake::HTTPD';
test_requires 'Test::More';

auto_install;
WriteAll;
