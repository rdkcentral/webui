<?php
/*
 If not stated otherwise in this file or this component's Licenses.txt file the
 following copyright and licenses apply:

 Copyright 2018 RDK Management

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/
?>
<?php
    /*
 * Set the Locale for the Web UI based on the LANG setting or current linux locale
 */
$locale = getenv("LANG");

if(isset($locale)) {
    if(!isset($_SESSION['language']) || setlocale(LC_MESSAGES, 0) != $locale){
        //putenv("LANG=" . $locale);
        setlocale(LC_MESSAGES, $locale);
        setlocale(LC_TIME, $locale);

        $domain = "rdkb";
        bindtextdomain($domain, 'locales');
        bind_textdomain_codeset($domain, 'UTF-8');
        textdomain($domain);
        $_SESSION['language'] = $locale; // set the default locale for future pages
    }
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <link rel="stylesheet" type="text/css" media="screen" href="./cmn/css/common-min.css" />
    <!--Character Encoding-->
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
    <script type="text/javascript" src="./cmn/js/lib/jquery-3.7.1.js"></script>
    <script type="text/javascript" src="./cmn/js/lib/jquery-migrate-1.2.1.js"></script>
    <script type="text/javascript" src="<?php 
        if((isset($locale)&&($locale!="")) && !strstr($locale, 'en')) { 
            echo './locales/'.$locale.'/cmn/js/lib/jquery.alerts.js';
        } else {
            echo './cmn/js/lib/jquery.alerts.js';
        }?>"></script>
</head>
<?php

require('includes/jwt.php');
$flag=0;
$flag_mso=0;
$passLockEnable = getStr("Device.UserInterface.PasswordLockoutEnable");
$failedAttempt=getStr("Device.Users.User.3.NumOfFailedAttempts");
$failedAttempt_mso=getStr("Device.Users.User.1.NumOfFailedAttempts");
$passLockoutAttempt=getStr("Device.UserInterface.PasswordLockoutAttempts");
$passLockoutTime=getStr("Device.UserInterface.PasswordLockoutTime");
$currentOpMode = getStr("Device.X_RDKCENTRAL-COM_EthernetWAN.CurrentOperationalMode");
$passLockoutTimeMins=$passLockoutTime/(1000*60);
$client_ip = $_SERVER["REMOTE_ADDR"];       // $client_ip="::ffff:10.0.0.101";
$server_ip = $_SERVER["SERVER_ADDR"];
$redirect_page = "https://{$_SERVER["SERVER_NAME"]}" . $_SERVER["PHP_SELF"];
header('X-robots-tag: noindex,nofollow');

    if (isset($_POST["username"]))
    {
		/*=============================================*/
		// $dev_mode = true;
		/*if (file_exists("/var/ui_dev_mode")) {
			$_SESSION["timeout"] = 100000; 
			if ($_POST["password"] == "dev") {
				create_session();
				if ($_POST["username"] == "mso") {
					header("location:at_a_glance.php");
				}
				elseif ($_POST["username"] == "admin") {
					header("location:at_a_glance.php");
				}			
				return; 
			} 
		}*/
		/*===============================================*/
        if ($_POST["username"] == "mso")
        {
            $authmode=getStr( "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.OAUTH.AuthMode" );
            if( $authmode != "sso" )
            {
                if( $authmode == "potd" || $_POST["password"] != "" )
                {
                    //triggering password validation in back end if "potd" or "mixed" and a password is supplied
                    $return_status = setStr("Device.Users.User.1.X_CISCO_COM_Password",$_POST["password"],true);
                    sleep(1);
                    $curPwd1 = getStr("Device.Users.User.1.X_CISCO_COM_Password");
                }
                else
                {
                    $curPwd1 = "Invalid_PWD";    // trigger SSO login attempt
                }
            }
            else
            {
                $curPwd1 = "Invalid_PWD";    // trigger SSO login attempt
            }
            if ( innerIP($client_ip) || ( (if_type($server_ip)=="rg_ip") && (strtolower($currentOpMode) !="ethernet") ) )
            {
                if($passLockEnable == "true")
                {
                    if($failedAttempt_mso<$passLockoutAttempt){
                        $failedAttempt_mso=$failedAttempt_mso+1;
                        setStr("Device.Users.User.1.NumOfFailedAttempts",$failedAttempt_mso,true);
                     }

                     if($failedAttempt_mso==$passLockoutAttempt){
                         $flag_mso=1;
                         echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
                     }
                }
                if($flag_mso==0){
                    session_destroy();
                    echo '<script type="text/javascript"> alert("'._("Access denied!").'"); history.back(); </script>';
                }
            }
            elseif ($curPwd1 == "Good_PWD" && $return_status)
            {
                if(($passLockEnable == "true") && ($failedAttempt_mso==$passLockoutAttempt)){
                    $flag_mso=1;
                    echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
                }
                else{
                    create_session();
                    $failedAttempt_mso=0;
                    setStr("Device.Users.User.1.NumOfFailedAttempts",$failedAttempt_mso,true);
                    exec("/usr/bin/logger -t GUI -p local5.notice 'User:mso login'");
                    header("location:at_a_glance.php");
                }
            }
            elseif ("" == $curPwd1)
            {
                session_destroy();
                echo '<script type="text/javascript"> alert("'._("Can not get password for mso from backend!").'"); history.back(); </script>';
            }
            else
            {
                $authendpoint=getStr( "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.OAUTH.ServerUrl" );
                if( $authmode != "potd" && $authendpoint )
                {
                    if (!isset($_GET['code']))
                    {
                        $auth_url = getAuthenticationUrl( $authendpoint, $redirect_page );
                        echo "<script type='text/javascript'>document.location.href='{$auth_url}';</script>";
                        die('_("Please wait ...")');
                    }
                }
                else
                {
                    if($passLockEnable == "true"){

                        if($failedAttempt_mso<$passLockoutAttempt){
                            $failedAttempt_mso=$failedAttempt_mso+1;
                            setStr("Device.Users.User.1.NumOfFailedAttempts",$failedAttempt_mso,true);
                        }

                        if($failedAttempt_mso==$passLockoutAttempt){
                            $flag_mso=1;
                            echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
                        }
                    }

                    if($flag_mso==0){
                        session_destroy();
                        echo '<script type="text/javascript"> alert("'._("Incorrect password for mso!").'"); history.back(); </script>';
                    }
                }
            }
        }
        elseif ($_POST["username"] == "admin")
		{
			$return_status = setStr("Device.Users.User.3.X_RDKCENTRAL-COM_ComparePassword",$_POST["password"],true);
			sleep(1);
			$passVal= getStr("Device.Users.User.3.X_RDKCENTRAL-COM_ComparePassword");
			if(!$return_status) $passVal = "Invalid_PWD";
			if ( !innerIP($client_ip) && (if_type($server_ip)!="rg_ip") )
				{
					if($passLockEnable == "true"){
							if($failedAttempt<$passLockoutAttempt){
								$failedAttempt=$failedAttempt+1;
								setStr("Device.Users.User.3.NumOfFailedAttempts",$failedAttempt,true);
							}
							if($failedAttempt==$passLockoutAttempt){
								$flag=1;
								echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
							}
					}
					if($flag==0){
						session_destroy();
						echo '<script type="text/javascript"> alert("'._("Access denied!").'"); history.back(); </script>';
					}
				}
				else if($passVal=="Invalid_PWD"){

					setStr("Device.DeviceInfo.X_RDKCENTRAL-COM_UI_ACCESS","ui_failed",true);
					session_destroy();
					if($passLockEnable == "true"){
						if($failedAttempt<$passLockoutAttempt){
						$failedAttempt=$failedAttempt+1;
						setStr("Device.Users.User.3.NumOfFailedAttempts",$failedAttempt,true);
						}
						if($failedAttempt==$passLockoutAttempt){
							$flag=1;
							echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
						}
					}
					if($flag==0){
						session_destroy();
						echo '<script type="text/javascript"> alert("'._("Incorrect password for admin!").'");history.back(); </script>';
					}
				}
				else
				{
					if(($passLockEnable == "true") && ($failedAttempt==$passLockoutAttempt)){
							$flag=1;
							echo '<script type="text/javascript"> alert("'.sprintf(_("You have %d failed login attempts and your account will be locked for %d minutes"), $passLockoutAttempt, $passLockoutTimeMins).'");history.back();</script>';
					}else{
						$failedAttempt=0;
						setStr("Device.Users.User.3.NumOfFailedAttempts",$failedAttempt,true);
						exec("/usr/bin/logger -t GUI -p local5.notice 'User:admin login'");
						setStr("Device.DeviceInfo.X_RDKCENTRAL-COM_UI_ACCESS","ui_success",true);
						if($passVal=="Default_PWD"){
							create_session();
							$_SESSION["password_change"] = "default_pwd";
							echo '<script type="text/javascript"> alert("You are using default password. Please change the password.");
								location.href = "admin_password_change.php";
							</script>';
						}else{
							create_session();
							header("location:at_a_glance.php");
						}
					}
				}
		}
        else
        {
		    setStr("Device.DeviceInfo.X_RDKCENTRAL-COM_UI_ACCESS","ui_failed",true);
            if( session_status() == PHP_SESSION_ACTIVE )
            {
                session_destroy();
            }
            echo '<script type="text/javascript"> alert("'._("Incorrect user name!").'"); history.back(); </script>';
        }
    }
    else
    {
        if (isset($_GET['token']))
        {
            $ADToken = $_GET['token'];
            $tokenvalid = VerifyToken( $ADToken );
            if( $tokenvalid == true )
            {
                $failedAttempt_mso=0;
                setStr("Device.Users.User.1.NumOfFailedAttempts",$failedAttempt_mso,true);
                exec("/usr/bin/logger -t GUI -p local5.notice 'User:mso login'");
                header("location:at_a_glance.php");
                create_session();
                // since $_POST["username"] is empty when we get a token, we'll set it in the $_SESSION["loginuser"]
                // to mso because that's the only user that can get the JWT. Later Web GUI processing requires it to b
                $_SESSION["loginuser"] = "mso";
                $_SESSION['JWT_VALID'] = true;
            }
            else
            {
                setStr("Device.DeviceInfo.X_RDKCENTRAL-COM_UI_ACCESS","token_failed",true);
                if( session_status() == PHP_SESSION_ACTIVE )
                {
                    session_destroy();
                }
                echo '<script type="text/javascript"> alert("'._("Access Denied, level is none!").'"); history.back(); </script>';
            }
        }
        else
        {
            setStr("Device.DeviceInfo.X_RDKCENTRAL-COM_UI_ACCESS","token_fetch",true);
            if( session_status() == PHP_SESSION_ACTIVE )
            {
                session_destroy();
            }
            echo '<script type="text/javascript"> alert("'._("Access Denied,  unknown error").'"); history.back(); </script>';
        }
    }
	function innerIP($client_ip){		//for compatibility, $client_ip is not used
		$out		= array();
		$tmp		= array();
		$lxc_check	= array();
		$lan_ip		= array();
		$server_ip	= $_SERVER["SERVER_ADDR"];
		if (strpos($server_ip, ".")){		//ipv4, something like "::ffff:10.1.10.1"
			$tmp		= explode(":", $server_ip);
			$server_ip	= array_pop($tmp);
		}
		exec('grep -a container=lxc /proc/1/environ', $lxc_check, $status);//use eth0 if webserver is running in lxc
			if (0==$status && $_POST["username"] == "admin") {
				exec("ifconfig eth0", $out);
			} else {
				exec("ifconfig brlan0", $out);
			}
		foreach ($out as $v){
			if (strpos($v, 'inet addr')){
				$tmp = explode('Bcast', $v);
				$tmp = explode('addr:', $tmp[0]);
				array_push($lan_ip, trim($tmp[1]));
			}
			else if (strpos($v, 'inet6 addr')){
				$tmp = explode('Scope', $v);
				$tmp = explode('addr:', $tmp[0]);
				$tmp = explode('%', $tmp[1]);
				$tmp = explode('/', $tmp[0]);
				array_push($lan_ip, trim($tmp[0]));
			}
		}
		return in_array($server_ip, $lan_ip);
	}
 	function get_ips($if_name){
		$out = array();
		$tmp = array();
		$ret = array();
		exec("ip addr show ".$if_name, $out);
		foreach ($out as $v){
			if (strstr($v, 'inet')){
				$tmp = explode('/', $v);
				$tmp = explode(' ', $tmp[0]);
				array_push($ret, trim(array_pop($tmp)));
			}
		}
		return $ret;
	}
	function if_type($ip_addr){
		$is_dummy_wan0 = getenv("WAN0_IS_DUMMY");
		$tmp = array();
		$lxc_check = array();
		$lan_ip	= get_ips("brlan0");
		exec('grep -a container=lxc /proc/1/environ', $lxc_check, $status);//use eth0 if webserver is running in lxc
		if (0==$status) {
			$cm_ip  = get_ips("eth0");
		} 
		else
                {  
                    if ($is_dummy_wan0 == "true")
                    {   
		        $cm_ip  = get_ips("privbr");
	            }
	            else
	            {
		        $cm_ip  = get_ips("wan0");
                    }
                }    
		if (strstr($ip_addr, ".")){		//ipv4, something like "::ffff:10.1.10.1"
			$tmp	 = explode(":", $ip_addr);
			$ip_addr = array_pop($tmp);
		}
		if (in_array($ip_addr, $lan_ip)){
			return "lan_ip";
		}
		else if (in_array($ip_addr, $cm_ip)){
			return "cm_ip";
		}
		else{
			return "rg_ip";
		}
		// print_r($lan_ip);
		// print_r($cm_ip);
	}
	function create_session(){
		session_start();
		
		/*
		 * Set the Locale for the Web UI based on the LANG setting or current linux locale
		 */
		$locale = getenv("LANG");
		if(isset($locale)) {
		    if(!isset($_SESSION['language']) || setlocale(LC_MESSAGES, 0) != $locale){
		        //putenv("LANG=" . $locale);
		        setlocale(LC_MESSAGES, $locale);
		        setlocale(LC_TIME, $locale);
		        
		        $domain = "rdkb";
		        bindtextdomain($domain, 'locales');
		        bind_textdomain_codeset($domain, 'UTF-8');
		        textdomain($domain);
		        $_SESSION['language'] = $locale; // set the default locale for future pages
		    }
		}
		//echo("You are logging...");
		$timeout_val 		= intval(getStr("Device.X_CISCO_COM_DeviceControl.WebUITimeout"));
		("" == $timeout_val) && ($timeout_val = 900);
		$_SESSION["timeout"]	= $timeout_val - 60;	//dmcli param is returning 900, GUI expects 840 - then GUI adds 60
		$_SESSION["sid"]	= session_id();
                if (isset($_POST["username"]))
                {
                    $_SESSION["loginuser"]	= $_POST["username"];
                }
	}

function getAuthenticationUrl( $auth_endpoint, $redirect_uri )
{
    $parameters = array(
        'ip_uri'  => $redirect_uri
    );
    return $auth_endpoint . '?' . http_build_query($parameters, null, '&');
}

/*	
	function innerIP($client_ip)
	{
		if (strstr($client_ip, "192.168.100.") && ("bridge-static"==getStr("Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode")))
		{
			return true;
		}
		if (strpos($client_ip, "."))		//IPv4
		{
			$tmp0	= explode(":", $client_ip);
			$tmp1	= array_pop($tmp0);
			$client	= explode(".", $tmp1);
			$lanip4	= explode(".", getStr("Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanIPAddress"));
			$lanmsk	= explode(".", getStr("Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanSubnetMask"));
			for ($i=0; $i<4; $i++)
			{
				if (((int)$lanmsk[$i]&(int)$client[$i]) != ((int)$lanmsk[$i]&(int)$lanip4[$i]))
				{
					return false;
				}
			}	
		}
		else
		{
			$prefix_dm	= getStr("Device.RouterAdvertisement.InterfaceSetting.1.Prefixes");
			$client		= explode(":", $client_ip);		
			$prefix		= explode(":", $prefix_dm);
			$prelen		= explode("/", $prefix_dm);
			$intlen		= intval(array_pop($prelen))/16;
			($intlen < 1) && ($intlen = 1);
			if (strtolower($client[0]) != "fe80")
			{
				for ($i=0; $i<$intlen; $i++)
				{
					if ($client[$i]!=$prefix[$i])
					{
						return false;
					}
				}
			}
		}
		return true;
	}
*/
?>
