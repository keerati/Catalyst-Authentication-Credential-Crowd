use inc::Module::Install 0.65;

name 'Catalyst-Authentication-Credential-Crowd';
all_from 'lib/Catalyst/Plugin/Authentication/Credential/Crowd.pm';

requires 'Catalyst::Runtime';
requires 'Catalyst::Plugin::Authentication';
requires 'HTTP::Request';
requires 'LWP::UserAgent';
requires 'JSON';
requires 'Test::Fake::HTTPD';

auto_install;
WriteAll;
