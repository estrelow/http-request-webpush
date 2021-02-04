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

#References:
#
# Tutorials and code samples:
#  https://developers.google.com/web/updates/2016/03/web-push-encryption
#  https://developers.google.com/web/fundamentals/push-notifications/web-push-protocol
#  https://adiary.adiary.jp/0391
# Standards:
#  https://tools.ietf.org/html/rfc8291

#================================================================
# hkdf()
#
# Calculates a key derivation using HMAC
# This is a simplified version based on Mat Scales jscript code
# see https://developers.google.com/web/updates/2016/03/web-push-encryption
#
# Notes: all args are expected to be binary strings, as the result
#================================================================
sub _hkdf($$$$$) {
   my $self=shift();
   my $salt=shift();
   my $ikm=shift();
   my $info=shift();
   my $len=shift();

   my $key=hmac_sha256($ikm,$salt);
   my $infoHmac= hmac_sha256($info,chr(1),$key);  

   return substr($infoHmac,0,$len);
}


sub subscription($$) {

   my $self=shift();
   my $subscription=shift();

   my $agent;

   if (ref $subscription eq 'HASH') {
      $agent=$subscription;
   } else {
      try {$agent=from_json($subscription); };
   }

   croak "Can't process subscription object" unless ($agent);
   croak "Subscription must include endpoint" unless (exists $agent->{endpoint});

   $self->uri($agent->{endpoint});
   $self->{subcription}=$agent;
   return $agent;
}

sub auth($@) {

   my $self=shift();

   if (scalar @_ == 2) {
      $self->{'app-pub'}=shift();
      $self->{'app-key'}=shift();
   } elsif (scalar (@_) == 1 && ref $_ eq 'Crypt::PK::ECC') {
      $self->{'app-pub'}=$_->export_key_raw('public');
      $self->{'app-key'}=$_->export_key_raw('private');
   }
}

sub authbase64($$$) {

   my $self=shift();
   my $pub=decode_base64url(shift());
   my $key=decode_base64url(shift());
   return $self->auth($pub,$key);
}

sub reuseecc($$) {

   my $self=shift();
   return $self->{'ecc'}=shift();
}

sub subject($$) {
   my $self=shift();
   return $self->{'subject'}=shift();
}

sub encode($$) {

   my $self=shift();
   my $enc=shift();

   #This method is inherited from HTTP::Message, but here only aes128gcm applies
   croak 'Only aes128gcm encoding available' unless ($enc eq 'aes128gcm');

   #Check prerequisites
   croak 'Endpoint must be present for message encoding' unless ($self->url());
   croak 'Authentication keys must be present for message encoding' unless ($self->{'app-key'});
   croak 'UA auth params must be present for message encoding' unless ($self->{subscription}->{'keys'}->{'p256dh'} && $self->{subscription}->{'keys'}->{'auth'});

   
}

sub new($%) {

   my ($class, %opts)=@_;

   my $self= $class->SUPER::new();
   $self->method('POST');

   bless $class, $self;

   my @Options= ('auth','subscription','authbase64','reuseecc','subject');
   for (@Options) {
      &$_($self,$opts{$_}) if (exists $opts{$_});
   }

}


1;

=pod

=encoding UTF-8

=head1 NAME

HTTP::Request::Webpush - HTTP Request for web push notifications

=head1 VERSION

version 0.01

=head1 SYNOPSIS

  some here


=head1 DESCRIPTION

C<HTTP::Request::Webpush> produces an HTTP::Request for Application-side Webpush
notifications as described on RFC8291. In this scheme, an Application is a 
server-side component that sends push notification to previously subscribed
browser workers. This class only covers the Application role. A lot must 
be done on the browser side to setup a full working push notification system.

In practical terms, this class is a glue for all the encription steps involved
in setting up a RFC8291 message, along with the RFC8292 VAPID scheme.

=over 4

=item $r->subscription($hash_reference)

=item $r->subscription('{"endpoint":"https://foo/fooer","expirationTime":null,"keys":{"p256dh":"BCNS...","auth":"dZ..."}}');

This sets the subcription object related to this notification service. This should be the same object
returned inside the browser environment using the PushManager.subscribe() method. The argument can
be either a JSON string or a previously setup hash reference.

=item $r->auth($pk) #pk being a Crypt::PK::ECC ref

=item $r->auth($pub_bin, $priv_bin)

=item $r->authbase64('BCAI00zPAbxEVU5w8D1kZXVs2Ro--FmpQNMOd0S0w1_5naTLZTGTYNqIt7d97c2mUDstAWOCXkNKecqgS4jARA8','M6xy5prDBhJNlOGnOkMekyAQnQSWKuJj1cD06SUQTow')

This sets the authentification key for the VAPID authentication scheme related to the push service.
This can either be a (public, private) pair or an already setup Crypt::PK::ECC object. The public part
must be the same used earlier in the browser environment in the PushManager.subscribe() applicationServerKey option.
The key pair can be passed as URL safe base64 strings using the authbase64() variant.

=item $r->reuseecc($ecc) #ecc being a Crypt::PK::ECC ref

By default, HTTP::Request::Webpush creates a new P-256 key pair for the encryption
step each time. In large push batches this can be time consuming. You can
reuse the same previously setup key pair in repeated messages using this method.

=item $r->subject('mailto:jdoe@some.com')

This establish the contact information related to the origin of the push service. This method
isn't enforced since RFC8292 mentions this as a SHOULD practice. But, if a valid contact information
is not included, the browser push service is likely to bounce the message. The URI passed is 
used as the 'sub' claim in the authentication JWT.

=back

=cut

__END__
