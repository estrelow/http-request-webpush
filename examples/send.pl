#!/usr/bin/perl
use strict;
use warnings;

use HTTP::Request::Webpush;
use LWP::UserAgent;

my $server_key = { public => 'BCAI00zPAbxEVU5w8D1kZXVs2Ro--FmpQNMOd0S0w1_5naTLZTGTYNqIt7d97c2mUDstAWOCXkNKecqgS4jARA8',
   private => 'M6xy5prDBhJNlOGnOkMekyAQnQSWKuJj1cD06SUQTow'};

my $send=HTTP::Request::Webpush->new();

$send->subscription('{"endpoint":"https://fcm.googleapis.com/fcm/send/cNwZxU5rL1I:APA91bEVVZDjabeF6woURsF5jci3RjdDtkAb4QrUx295L9wxXaxrb7kKSkMnKaNSSwI18Lbv8S40fAkHFDvcXeq4DlE15ErGnzdTniYluSeZKh28kjqiuT7xIg75nnySAKILMjCzQBx-","expirationTime":null,"keys":{"p256dh":"BCNSUztj4OFfIOqZNt2cDg0vICWiaYtxNRN48rd5fp8roNQuNWlVoIZuIr-49hOwgJxadqy7rVnkqiuk8GZ6b0Q","auth":"dZ4T8XDVH_u9QhcXQSFUiQ"}}');
$send->subject('mailto:esf@moller.cl');
$send->authbase64($server_key->{public}, $server_key->{private});
$send->content("Billy Jean's not my lover");
$send->encode;
$send->header('TTL' => '90');

my $ua = LWP::UserAgent->new;
my $response = $ua->request($send);

print $response->code();
print "\n";
print $response->decoded_content;
print $response->header('Location');
print "\n";
print $response->header('Link');


