#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

source /lib/rdk/t2Shared_api.sh
source /etc/device.properties

echo "setenv.add-environment = (\
\"WAN0_IS_DUMMY\" => \"$WAN0_IS_DUMMY\"
)"

#WEBGUI_SRC=/fss/gw/usr/www/html.tar.bz2
#WEBGUI_DEST=/var/www

#if test -f "$WEBGUI_SRC"
#then
#	if [ ! -d "$WEBGUI_DEST" ]; then
#		/bin/mkdir -p $WEBGUI_DEST
#	fi
#	/bin/tar xjf $WEBGUI_SRC -C $WEBGUI_DEST
#else
#	echo "WEBGUI SRC does not exist!"
#fi
if [ -z $1 ] && [ ! -f /tmp/webuifwbundle ]; then
    if [ ! -f /nvram/certs/myrouter.io.cert.pem ] || [ -f /etc/webui-cert-bundle*.tar ]; then
        if [ -f /lib/rdk/check-webui-update.sh ]; then
            sh /lib/rdk/check-webui-update.sh
        else
            echo "check-webui-update.sh not available means webuiupdate support is disabled"
        fi
    else
        echo "certificate /nvram/certs/myrouter.io.cert.pem or webui bundle not available"
    fi
fi

if [ "x$BOX_TYPE" != "xrpi" ] && [ "x$BOX_TYPE" != "xturris" ] && [ "x$BOX_TYPE" != "xemulator" ]; then
#upstreamed webgui_script_https_support.patch to Secure webui redirection as part of RDKB-42686.
mkdir -p /tmp/.webui/
ID="/tmp/trpfizyanrln"
itr=0

while [ $itr -le 10 ]
do
echo "In GetConfig loop"
if [ -f /nvram/certs/myrouter.io.cert.pem ]; then
    if [ ! -f /usr/bin/GetConfigFile ];then
        echo "Error: GetConfigFile Not Found"
        exit 127
    fi
	    GetConfigFile $ID
	    if [ ! -f $ID ]; then
		    echo "sleeping for 30 seconds"
		    sleep 30
		    itr=`expr $itr + 1`
		    continue
	    fi
	    cp /nvram/certs/myrouter.io.cert.pem /tmp/.webui/
	    #lighttpd expects file with key and pem
	    cat /tmp/.webui/myrouter.io.cert.pem >> $ID
	    break
else
	itr=`expr $itr + 1`
	echo "sleeping for 30 seconds"
	sleep 30
fi

done
if [ ! -f /tmp/trpfizyanrln ];then
	echo "Error: Lighttpd key is not generated"
	exit 1
fi
fi

# start lighttpd
source /etc/utopia/service.d/log_capture_path.sh
# setup non-root related file-permission for lighttpd
touch /rdklogs/logs/lighttpderror.log
chown non-root:non-root /rdklogs/logs/lighttpderror.log
touch /rdklogs/logs/webui.log
chown non-root:non-root /rdklogs/logs/webui.log
if [ "x$BOX_TYPE" != "xHUB4" ]; then
    source /fss/gw/etc/utopia/service.d/log_env_var.sh
fi
REVERT_FLAG="/nvram/reverted"
LIGHTTPD_CONF="/etc/lighttpd.conf"
LIGHTTPD_CONF_TXT="/tmp/lighttpdconfig.txt"
FILE_LOCK="/tmp/webgui.lock"
MAX_RETRY_COUNT=10
webgui_count=0
export LANG=

#Only one process should create conf file and start lighttpd at a time
while : ; do
    if [ $webgui_count -lt $MAX_RETRY_COUNT ]; then
        if [ -f $FILE_LOCK ]; then
            echo "WEBGUI :Sleeping,Another instance running"
            sleep 1;
            webgui_count=$((webgui_count+1))
            echo "Retry count = $webgui_count"
            continue;
        else
            # Creating lock to allow one process at a time
            touch $FILE_LOCK
            break;
        fi
    else
        echo "WEBGUI: Exiting, another instance is running and max retry reached"
        exit 1
    fi
done

LIGHTTPD_PID=`pidof lighttpd`
if [ "$LIGHTTPD_PID" != "" ]; then
	/bin/kill -9 $LIGHTTPD_PID
fi
#upstreamed webgui_remove_dynamic_configs.patch as part of RDKB-42686

#Changes for ArrisXb6-2949

if [ ! -d "/tmp/pcontrol" ]
then
     mkdir /tmp/pcontrol
fi

cp -rf /usr/www/cmn/ /tmp/pcontrol
#Dynamically create pause screen file 
#removed chmod as part of CISCOXB3-6294 since etc is read-only FileSystem
sh /etc/pauseBlockGenerateHtml.sh

WIFIUNCONFIGURED=`syscfg get redirection_flag`
SET_CONFIGURE_FLAG=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges`

#Read the http response value
NETWORKRESPONSEVALUE=`cat /var/tmp/networkresponse.txt`

iter=0
max_iter=2
while [ "$SET_CONFIGURE_FLAG" = "" ] && [ "$iter" -le $max_iter ]
do
	iter=$((iter+1))
	echo "$iter"
	SET_CONFIGURE_FLAG=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges`
done
echo "WEBGUI : NotifyWiFiChanges is $SET_CONFIGURE_FLAG"
echo "WEBGUI : redirection_flag val is $WIFIUNCONFIGURED"

restartEventsForRfCp()
{
    echo "WEBGUI : restart norf cp events restart"
    sysevent set norf_webgui 1
    sysevent set firewall-restart
    sysevent set zebra-restart
    sysevent set dhcp_server-stop
    # Let's make sure dhcp server restarts properly
    sleep 1
    sysevent set dhcp_server-start
    dibbler-server stop
    dibbler-server start
}

# Function to check if wan_fail_over is enabled or not
# return 1 if wan_fail_over is enabled
# return 0 if wan_fail_over is disabled
checkForWanFailOver()
{
    echo_t "Network Response: checkForWanFailOver"
    currentWanIf=`sysevent get current_wan_ifname`
    defaultWanIf=`sysevent get wan_ifname`
    echo_t "currentWanIf: $currentWanIf  defaultWanIf: $defaultWanIf"
    if [ "x$currentWanIf" = "x" ] || [ "$currentWanIf" == "$defaultWanIf" ];then
        AllowRemoteInterfaces=`dmcli eRT getv Device.X_RDK_WanManager.AllowRemoteInterfaces | grep value | cut -f3 -d : | cut -f2 -d" "`
        Interface_Available_Status=`dmcli eRT getv Device.X_RDK_WanManager.InterfaceAvailableStatus | grep -i "REMOTE_LTE,1"`
        echo_t "AllowRemoteInterfaces: $AllowRemoteInterfaces  Interface_Available_Status: $Interface_Available_Status"
        if [[ "x$Interface_Available_Status" != "x" ]] && [ "$AllowRemoteInterfaces" = "true" ]
        then
            #LTE wan interface is available
            echo_t "Network Response: checkForWanFailOver : enabled"
            return 1
        else
            echo_t "Network Response: checkForWanFailOver : disabled"
            return 0
        fi
    else
        echo_t "Network Response: checkForWanFailOver : enabled"
        return 1
    fi
}

# Check if unit has proper RF signal
checkRfStatus()
{
    noRfCp=0
    checkForWanFailOver
    wfoStatus=$?
    echo_t "WEBGUI: wfoStatus: $wfoStatus"
    if [ "$wfoStatus" = "0" ]
    then
        RF_SIGNAL_STATUS=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_CableRfSignalStatus | grep value | cut -f3 -d : | cut -f2 -d" "`
        isInRfCp=`syscfg get rf_captive_portal`
        echo_t "WEBGUI: values RF_SIGNAL_STATUS : $RF_SIGNAL_STATUS , isInRfCp: $isInRfCp"
        if [ "$RF_SIGNAL_STATUS" = "false" ] || [ "$isInRfCp" = "true" ]
        then
            noRfCp=1
        else
            noRfCp=0
        fi

        if [ $noRfCp -eq 1 ]
        then
            echo_t "WEBGUI: Set rf_captive_portal true"
            syscfg set rf_captive_portal true
            syscfg commit
            return 1
        else
            return 0
        fi
    else
        return 0
    fi
} 


if [ "$BOX_TYPE" = "XB6" ]
then

    # P&M up will make sure CM agent is up as well as
    # RFC values are picked
    echo_t "No RF CP: Check PAM initialized"
    PAM_UP=0
    while [ $PAM_UP -ne 1 ]
    do
    sleep 1
    #Check if CcspPandMSsp is up
    # PAM_PID=`pidof CcspPandMSsp`

    if [ -f "/tmp/pam_initialized" ]
    then
         PAM_UP=1
    fi
    done
    echo_t "RF CP: PAM is initialized"

    enableRFCaptivePortal=`syscfg get enableRFCaptivePortal`
    ethWanEnabled=`syscfg get eth_wan_enabled`
    cpFeatureEnbled=`syscfg get CaptivePortal_Enable`

   # Enable RF CP in first iteration. network_response.sh will run once WAN comes up
   # network_response.sh will take the unit out of RF CP 
   if [ "$enableRFCaptivePortal" != "false" ] && [ "$ethWanEnabled" != "true" ] && [ "$cpFeatureEnbled" = "true" ]
   then
       checkRfStatus 
       isRfOff=$?
       echo_t "WEBGUI: RF status returned is: $isRfOff"
       if [ "$isRfOff" = "1" ]
       then
          echo_t "WEBGUI: Restart events for RF CP"
          restartEventsForRfCp
       fi
   fi
fi

if [ "$WIFIUNCONFIGURED" = "true" ]
then
	if [ "$NETWORKRESPONSEVALUE" = "204" ] && [ "$SET_CONFIGURE_FLAG" = "true" ]
	then
		while : ; do
		echo "WEBGUI : Waiting for PandM to initalize completely to set ConfigureWiFi flag"
		CHECK_PAM_INITIALIZED=`find /tmp/ -name "pam_initialized"`
		echo "CHECK_PAM_INITIALIZED is $CHECK_PAM_INITIALIZED"
  	        	if [ "$CHECK_PAM_INITIALIZED" != "" ]
   			then
			   echo "WEBGUI : WiFi is not configured, setting ConfigureWiFi to true"
	         	   output=`dmcli eRT setvalues Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi bool TRUE`
			   check_success=`echo $output | grep  "Execution succeed."`
  	        		if [ "$check_success" != "" ]
   				then
     			 	   echo "WEBGUI : Setting ConfigureWiFi to true is success"
				uptime=`cat /proc/uptime | awk '{ print $1 }' | cut -d"." -f1`
				   echo_t "Enter_WiFi_Personalization_captive_mode:$uptime"
				   t2ValNotify "btime_wcpenter_split" $uptime
				   if [ -e "/usr/bin/onboarding_log" ]; then
				       /usr/bin/onboarding_log "Enter_WiFi_Personalization_captive_mode:$uptime"
				   fi
 	       			fi
      			   break
 	       		fi
		sleep 2
		done

		MAX_NUM_TRIES=20
                for ((i=1; i<=MAX_NUM_TRIES; i++ ));
                do
                    echo "WEBGUI : Waiting for WiFi Agent to initalize completely before captive portal"
                    CHECK_WIFI_INITIALIZED=`find /tmp/ -name "wifi_dml_complete"`
                    if [ "$CHECK_WIFI_INITIALIZED" != "" ]
                    then
                        echo "WEBGUI : WiFi Agent is initialized proceeding to captive portal"
                        break
                    fi

                    sleep 6 
                done

	else
		if [ ! -e "$REVERT_FLAG" ] && [ "$NETWORKRESPONSEVALUE" = "204" ]
		then
			# We reached here as redirection_flag is "true". But WiFi is configured already as per notification status.
			# Set syscfg value to false now.
			echo "WEBGUI : WiFi is already personalized... Setting redirection_flag to false"
			syscfg set redirection_flag false
			syscfg commit
			echo "WEBGUI: WiFi is already personalized. Set reverted flag in nvram"	
			touch $REVERT_FLAG
		fi
	fi
fi		

if [ "$MODEL_NUM" = "TG3482G" ] ; then
	# RDKB-15633 from Arris XB6
	RFC_CONTAINER_SUPPORT=`syscfg get containersupport`
	if [ "x$CONTAINER_SUPPORT" = "x1" -a  "x$RFC_CONTAINER_SUPPORT" = "xtrue" ]; then
	  touch /tmp/.lxcenabled
	  echo "WEBGUI: Started in Container."
	else
	  LD_LIBRARY_PATH=/fss/gw/usr/ccsp:$LD_LIBRARY_PATH lighttpd -f $LIGHTTPD_CONF

	  echo "WEBGUI: Started without Container."
	fi
else
	  LD_LIBRARY_PATH=/fss/gw/usr/ccsp:$LD_LIBRARY_PATH lighttpd -f $LIGHTTPD_CONF

fi

echo "WEBGUI : Set event"
sysevent set webserver started
touch /tmp/webgui_initialized


#upstreamed webgui_TCXB6_2988.patch as part of RDKB-42686
if [ "$MANUFACTURE" = "Technicolor" ]
then
	#Added fix for TCXB6-2988

	CAPTIVEPORTAL_ENABLED=`syscfg get CaptivePortal_Enable`
 	 echo_t "WEBGUI : CaptivePortal enabled val is $CAPTIVEPORTAL_ENABLED"

	REDIRECTION_FLAG=`syscfg get redirection_flag`
  	 echo_t "REDIRECTION_FLAG got is : $REDIRECTION_FLAG"

 	if [ "$REDIRECTION_FLAG" = "true" ] && [ "$CAPTIVEPORTAL_ENABLED" == "true" ]
 	then
         	#Check if lighttpd daemon is up
         	CHECK_LIGHTTPD=`pidof lighttpd`

         	iter=0
         	max_iter=30
        	while [ "$CHECK_LIGHTTPD" = "" ] && [ "$iter" -le $max_iter ]
         	do
            	   iter=$((iter+1))
            	   #echo_t "$iter"
            	   CHECK_LIGHTTPD=`pidof lighttpd`
            	   sleep 1
         	done

         	if [ "$CHECK_LIGHTTPD" != "" ]
         	then
              		echo_t "WEBUI : LIGHTTPD IS UP"
              		uptime=`cat /proc/uptime | awk '{ print $1 }' | cut -d"." -f1`
              		echo_t "Enter_WiFi_Personalization_captive_mode:$uptime"
         	fi
  	fi
fi

#Removing the lock
rm -f $FILE_LOCK
#Upstreamed webgui_sh.patch(SKYH4-3996) as part of RDKB-42686
if [[ $MANUFACTURE == SKY* ]]
then
	rm -rf /tmp/.webui
	rm $ID
fi

if [[ $MANUFACTURE == SKY* ]]
then
	echo "url.access-deny = ( \"~\", \".inc\", \".html\" )" >> $LIGHTTPD_CONF_TXT
else
	echo "url.access-deny = ( \"~\", \".inc\", \".html\", \".json\" )" >> $LIGHTTPD_CONF_TXT
fi
