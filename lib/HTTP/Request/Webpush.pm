package HTTP::Request::Webpush;

use strict 'vars';
use warnings;

our$VERSION='0.01';

use base 'HTTP::Request';

use JSON;
use Crypt::JWT qw(encode_jwt);
use MIME::Base64 qw( encode_base64url decode_base64url);
use Crypt::PRNG qw(random_bytes);
use Crypt::AuthEnc::GCM 'gcm_encrypt_authenticate';
use Crypt::PK::ECC 'ecc_shared_secret';
use Digest::SHA 'hmac_sha256';
use Carp;

sub new($%) {

   my ($class, %opts)=@_;

   croak 'subscription must me specified' unless (exists $opts{subscription});
   croak 'key must me specified' unless (exists $opts{key});

   my $self= $class->SUPER::new();
   $self->method('POST');

   my $agent;
   if (ref $opts{subscription} eq 'HASH') {
      $agent=$opts{subscription};
   } else {
      $agent=decode_json($opts{subscription});
   }

   croak "subscription spec must containt endpoint" unless (exists $agent->{endpoint});
   $self->uri($agent->{endpoint});
   
   
   
   
}


1;

=pod

=encoding UTF-8

=head1 NAME

HTTP::Request::Webpush - HTTP Request for web push notifications

=head1 VERSION

version 0.01

=cut

__END__
