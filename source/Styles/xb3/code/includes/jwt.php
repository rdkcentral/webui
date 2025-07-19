/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

<?php

$tid = "906aefe9-76a7-4f65-b82d-5ec20775d5aa";
$JWTdir = "/tmp/.jwt/";
$PUBKEYFILE = $JWTdir . "pubkey.cer";
$JWTkeyfile = $JWTdir . "keys";
$KeyURL = "https://login.microsoftonline.com/906aefe9-76a7-4f65-b82d-5ec20775d5aa/discovery/v2.0/keys";
$GetKeys = "/usr/bin/curl --connect-timeout 8 -o ". $JWTkeyfile . " " . $KeyURL;

function VerifyToken($token)
{

    if (!extension_loaded('openssl')) {
        throw new Exception('The PHP openssl extension is missing.');
    }

    $tokendata = "";   
    $tokensegs = explode('.', $token);
    $cnt = count($tokensegs);
    if( $cnt != 3) {
        $validtoken = false;
        throw new Exception('The JWT has an incorrect number of segments');
    }
    else
    {
        $validtoken = VerifySignature( $tokensegs[0], $tokensegs[1], $tokensegs[2] );
        if( $validtoken == true ) {
            $decodeddata = base64decode_url( $tokensegs[1] );
            $tokendata = json_decode( $decodeddata, true );
            $validtoken &= VerifyTokenData( $tokendata );
        }
        else
        {
            LogTokenData( "Signature Failed!!!", $validtoken );
        }
    }

    if( $validtoken == true )
    {
        LogTokenData( $tokendata, $validtoken );
    }
    else
    {
        LogTokenData( "Invalid Token Received", $validtoken );
    }

    return $validtoken;
}

function VerifySignature($header, $payload, $sig)
{
    global $JWTdir, $JWTkeyfile, $GetKeys, $PUBKEYFILE;
    $sigverified = false;

    if( file_exists( $JWTdir ) || mkdir($JWTdir) )
    {
        exec( $GetKeys );    // always try to download new list of keys.
        // but even if previous curl failed, see if old key file is still there.
        // it might work if it is. This could get you logged in if no server response.
        if( file_exists( $JWTkeyfile ) )
        {
            $modtimevalid = CheckModTimeValid( $JWTkeyfile );
            if( $modtimevalid == true )
            {
                $headerdecoded = base64decode_url( $header );
                $headerarr = json_decode( $headerdecoded, true );
    
                $keyfile = file_get_contents( $JWTkeyfile );
                if( $keyfile != false )    // doubtful this would be possible but just in case
                {
                    $keyarr = json_decode( $keyfile, true );
                    if( keyarr != null )
                    {
                        foreach ( $keyarr[ 'keys'] as $key ) {
                            if( $key['kid'] == $headerarr['kid'] ) {
                                WritePubKey( $key['x5c'][0] );
                                break;
                            }
                        }
                        $pubkey = "file://" . $PUBKEYFILE;
                        $pubkeyid = openssl_pkey_get_public( $pubkey );
                        $token = $header . '.' . $payload;
                        $sig2verify = base64decode_url( $sig );
                        $sigvalid = openssl_verify( $token, $sig2verify, $pubkeyid, 'SHA256' );
        
                        if( $sigvalid == 1 )
                        {
                            $sigverified = true;
                        }
                    }
                    else
                    {
                        unlink($JWTkeyfile);    // file is no good for some reason so remove it, it's useless
                        LogTokenData( " : Key file invalid json", false );
                    }
                }
                else
                {
                    unlink($JWTkeyfile);    // file is no good for some reason so remove it, it's useless
                    LogTokenData( " : Key file empty", false );
                }
            }
            else        // file modification time out of bounds
            {
                unlink($JWTkeyfile);    // file is no good for some reason so remove it, it's useless
                LogTokenData( " : Key file mod time invalid", false );
            }

            unlink($PUBKEYFILE);    // always delete if it exists. It's re-created every time key file is OK
        }
        else        // file is non-existent
        {
            LogTokenData( " : No key file found", false );
        }
    }

    return $sigverified;
}

function CheckModTimeValid($filename)
{
    var date = new Date();
    $fourhours = 4 * 3600;
    $modtimevalid = false;

    $curtime = parseInt( date.getTime()/1000 );
    $modtime = filemtime($filename);
    $fileage = $curtime - $modtime;
    if( $fileage >= 0 && $fileage <= $fourhours )
    {
        $modtimevalid = true;
    }
    return $modtimevalid;
}

function VerifyTokenData($tkdata)
{
    global $tid;
    $retval = false;
    $errstr = "";

    $curtime = time();
    $tokeniat = intval( $tkdata['iat'] );
    $tokennbf = intval( $tkdata['nbf'] );
    $tokenexp = intval( $tkdata['exp'] );

    if( ($curtime < $tokenexp)        // current time must be < expiration
        && ($curtime >= $tokennbf)    // current time must be >= not before time
        && ($curtime >= $tokeniat) )  // current time must be >= issued at time
    {
        if( $tkdata['tid'] == $tid )
        {
            $retval = true;
        }
        else
        {
            $errstr = "Error: Token fails Tenant ID, tid=" . $tkdata['tid'];
            $errstr = $errstr . ", userId=" . $tkdata['email'];
            LogTokenData( $errstr, false );
        }
    }
    else
    {
        $errstr = "Error: Token fails time validation, cur=" . $curtime;
        $errstr = $errstr . ", iat=" . $tokeniat . ", nbf=" . $tokennbf . ", exp=" . $tokenexp;
        $errstr = $errstr . ", userId=" . $tkdata['email'];
        LogTokenData( $errstr, false );
    }

    return $retval;
}

function WritePubKey($pubkey)
{
    global $PUBKEYFILE;

    $file = fopen( $PUBKEYFILE, "w" );
    if( $file != false )
    {
        $str = "-----BEGIN CERTIFICATE-----" . "\n";
        fwrite( $file, $str );
        $str = $pubkey . "\n";
        fwrite( $file, $str );
        $str = "-----END CERTIFICATE-----" . "\n";
        fwrite( $file, $str );
        fclose( $file );
    }
    else
    {
        LogTokenData( " : Unable to write public key file", false );
    }
}

function LogTokenData($tkdata, $usetoken)
{

    $file = fopen( "/rdklogs/logs/webui.log", "a" );
    if( $file != false )
    {
        $str = date("Y-m-d H:i:s");

        if( $usetoken == true )
        {
            $str = $str . " WebUI: OAUTH userId=" . $tkdata['email'];
            $str = $str . " expiration=" . $tkdata['exp'];
        }
        else
        {
            $str = $str . " " . $tkdata;
        }
        $str = $str . "\n";
        fwrite( $file, $str );
        fclose( $file );
    }
}

function base64decode_url($string)
{
   /* Need to map non-RFC-1421 characters in the URL to the proper base64 charset. */
   $data = str_replace( "-", "+", $string);
   $data = str_replace( "_", "/", $data);
   /* Decode input must be a multiple of 4 bytes so pad up with “=”. */
   $mod4 = strlen($data) % 4;

   switch ($mod4)
   {
       case 1:
           $data = $data."===";
           break;
       case 2:
           $data = $data."==";
           break;
       case 3:
           $data = $data."=";
           break;
    }
    return base64_decode($data);
}

?>
