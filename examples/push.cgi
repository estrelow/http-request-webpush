#!/usr/bin/perl
use strict 'vars';
use warnings;

use CGI;
use Config::IniFiles;
use JSON;
use HTTP::Request;
use LWP::UserAgent;
use Crypt::JWT qw(encode_jwt);
use MIME::Base64 qw( decode_base64 encode_base64 encode_base64url decode_base64url);
use Crypt::PRNG qw(random_bytes);
use Crypt::AuthEnc::GCM 'gcm_encrypt_authenticate';
use Crypt::PK::ECC 'ecc_shared_secret';
use Digest::SHA 'hmac_sha256';
use Encode 'encode_utf8';

my $req=new CGI;


my $cmd=$req->param('cmd') || $req->url_param('cmd');

#Defino la llave RSA con la que voy a conversar con el servicio push-web
my $server_key = { public => 'BCAI00zPAbxEVU5w8D1kZXVs2Ro--FmpQNMOd0S0w1_5naTLZTGTYNqIt7d97c2mUDstAWOCXkNKecqgS4jARA8',
   private => 'M6xy5prDBhJNlOGnOkMekyAQnQSWKuJj1cD06SUQTow'};

#=======================================================================================
# Este el el script que se instala en el cliente para mostrar las notificaciones
#=======================================================================================
my $worker= <<'EOJ';
// Register event listener for the 'push' event.
self.addEventListener('push', function(event) {
  // Retrieve the textual payload from event.data (a PushMessageData object).
  // Other formats are supported (ArrayBuffer, Blob, JSON), check out the documentation
  // on https://developer.mozilla.org/en-US/docs/Web/API/PushMessageData.
  const payload = event.data ? event.data.text() : 'no payload';

  // Keep the service worker alive until the notification is created.
  event.waitUntil(
    self.registration.showNotification('Venta Virtual VIVIEN', {
      body: payload,
    })
  );
});
EOJ

sub hkdf($$$$) {
   my $salt=shift();
   my $ikm=shift();
   my $info=shift();
   my $len=shift();

   my $key=hmac_sha256($ikm,$salt);
  
   return $key unless ($info);
   my $infoHmac= hmac_sha256($info,chr(1),$key);  

   return substr($infoHmac,0,$len);

}

sub createInfo($$$) {

   my $type=shift();
   my $clientkey=shift();
   my $serverkey=shift();

   my $info="Content-Encoding: $type".chr(0);
   $info .="P-256.".chr(0);
   $info .= pack('n',length($clientkey));
   $info .= $clientkey;
   $info .= pack('n',length($serverkey));
   $info .= $serverkey;
   return $info;

}



sub renderpush($$) {

   my $user=shift();
   my $session=shift();

   my $path=$req->url();
   my $cmd=$req->url(-relative => 1);
   #$path =~ s/\/$cmd$//;
   my $worker = "$path?cmd=service-worker.js";
   my $subscribe= "$path?cmd=subscribe";

   print <<"EOH";
<div class='push'>
<a href="#" onclick='return subscribe()'>Activar notificaciones</a>
<script type='text/javascript'>
function isSupported() {
  if (!('serviceWorker' in navigator)) {
    // Service Worker isn't supported on this browser, disable or hide UI.
    return false;
  }

  if (!('PushManager' in window)) {
    // Push isn't supported on this browser, disable or hide UI.
    return false;
  }

  return true;
}

// Web-Push
// Public base64 to Uint
function urlBase64ToUint8Array(base64String) {
    var padding = '='.repeat((4 - base64String.length % 4) % 4);
    var base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    var rawData = window.atob(base64);
    var outputArray = new Uint8Array(rawData.length);

    for (var i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function subscribe() {
  const result = await Notification.requestPermission();
  if (result == 'granted') {
    var r=await navigator.serviceWorker.register('$worker');
    var m=r.pushManager;
    const subscribeOptions = {
       userVisibleOnly: true,
       applicationServerKey: urlBase64ToUint8Array(
        '$server_key->{public}'
      )
    };

    var s= await m.subscribe(subscribeOptions); 
    var w=fetch('$subscribe', {
       method: 'POST',
       headers: {
         'Content-Type': 'application/json'
       },
       body: JSON.stringify(s)
        });
    }

   return true;
}
</script>

EOH
}

sub subscribe($) {

   my $opt=shift();
   my $conf=Config::IniFiles->new(-file => "push.conf", -nocase => 1);
   die "Falla conf" unless ($conf);
   $conf->newval('subscription','data',$opt);
   $conf->RewriteConfig;
   my $success='{ "data": { "success": "true" } }';
   print $req->header(-type => 'application/json', -Content_length => length($success));


}

sub postpush($$$) {

   my $session=shift();
   my $text=shift();
   my $link=shift();

   my $conf=Config::IniFiles->new(-file => "push.conf", -nocase => 1);
   die "Falla config" unless($conf);
   my $json=$conf->val($session,'data');
   my $keys=from_json($json);

   my $send=HTTP::Request->new(POST => $keys->{endpoint});

   my $payload= 'Hola, estamos todos bien';


   #This is the JWT part
   my $data={  
     'aud' => $keys->{endpoint},
     'exp'=> time() + 86400,
     'sub'=> 'mailto:esf@moller.cl'  
      };

   my $appk = Crypt::PK::ECC->new();
   $appk->import_key_raw(decode_base64url($server_key->{private}),'secp256r1');
   my $public=decode_base64url($server_key->{public});
   my $token = encode_jwt(payload => $data, key => $appk  , alg=>'ES256');
   $send->header( 'Authorization' => "WebPush $token" );
   #$send->header('Crypto-Key' => $server_key->{public});

   #Ahora encriptamos el mensaje
   my $salt=random_bytes(16);

   # $pk va a ser la llave de "sesión"
   my $pk = Crypt::PK::ECC->new();
   $pk->generate_key('prime256v1');
   my $pub_signkey=$pk->export_key_raw('public');
   my $sec_signkey=$pk->export_key_raw('private');
   
   #The p256dh key is given to us in X9.62 format. Crypt::PK::ECC should be able
   #to read it as a "raw" format. But it's important to apply the base64url variant
   my $ua_public=decode_base64url($keys->{'keys'}->{'p256dh'});
   my $sk=Crypt::PK::ECC->new();
   $sk->import_key_raw($ua_public, 'secp256r1');

   my $ecdh_secret=$pk->shared_secret($sk);
   my $auth_secret= decode_base64url($keys->{'keys'}->{'auth'});


   #Some docs establish this string as Content-Encoding: auth
   my $key_info="WebPush: info".chr(0).$ua_public.$pub_signkey;
   # HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
   # HKDF-Expand(PRK_key, key_info, L_key=32)
   my $prk=hkdf($auth_secret, $ecdh_secret, $key_info,32);

   # HKDF-Expand(PRK, cek_info, L_cek=16)
   my $cek_info='Content-Encoding: aes128gcm'.chr(0);
   my $cek=hkdf($salt,$prk,$cek_info,16);

   # HKDF-Expand(PRK, nonce_info, L_nonce=12)
   my $nonce_info='Content-Encoding: nonce'.chr(0);
   my $nonce= hkdf($salt, $prk,$nonce_info,12);

   my ($body, $tag) = gcm_encrypt_authenticate("AES", $cek, $nonce, '', $payload.chr(2).chr(0));
   $body = $salt."\x00\x00\x10\x00\x41".$pub_signkey.$body.$tag;

   $send->header('Encryption' => "salt=".encode_base64url($salt));
   $send->header('Crypto-Key' => "p256ecdsa=". $server_key->{public});
   $send->header('Content-Length' => length($body));
   $send->header('Content-Type' => 'application/octet-stream');
   $send->header('Content-Encoding' => 'aes128gcm');
   $send->header('TTL' => '90');

   $send->content($body);

   print "\np256:".encode_base64url($pub_signkey).", ".encode_base64url($sec_signkey);
   print "\nsalt:".encode_base64url($salt);
   print "\nIKM: ".encode_base64url($ecdh_secret);
   print "\nPRK: ".encode_base64url($prk);
   print "\nCEK: ".encode_base64url($cek);
   print "\nNONCE:".encode_base64url($nonce);
   print "\nPAYLOAD:".encode_base64url($body);

   my $ua = LWP::UserAgent->new;
   my $response = $ua->request($send);
   print $response->code();
   print "\n";
   print $response->decoded_content;
   print $response->header('Location');
   print "\n";
   print $response->header('Link');

}


if ($cmd eq 'service-worker.js') {
   print $req->header(-type       => 'application/javascript', -Content_length => length($worker));
   print $worker;
} elsif ($cmd eq 'subscribe') {
   subscribe($req->param('POSTDATA'));
}  elsif ($cmd eq 'send') {
   postpush('subscription','Hello world','url');

}   else {
   print $req->header('text/html');
   renderpush('x','y');
}

