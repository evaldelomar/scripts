<?php
    require_once("/usr/local/sap/saprfc-php7.0/saprfc.php"); 

    require_once("constants.php");
    //Read the wordlist

    $file = fopen(WORDLIST,"r"); $wordlist = array();

    while($line = fgets($file))
    {
        $line = str_replace("\t"," ",$line);
        $line = str_replace("\n","",$line);
        $line = str_replace("\r","",$line);
        $reg = explode(" ",$line,2);
        $wordlist[] = array("user" => $reg[0], "pass" => $reg[1]);
    }

    //Random user and password
    $randUser = bin2hex(random_bytes(4));
    $randPass = bin2hex(random_bytes(4));
    
    echo date("Y-m-d H:i:s",time())." - Starting check on SAP system ".SAP_IP.", number ".SAP_NR."\n";

    echo "\n-1- Discovering clients\n\n";

    $clients = array();
    for($i=0; $i<=999; $i++)
    {
        $client = substr("000".$i,-3);
        //$randUser = "evaldelomar"; $randPass = "Mefisto1!!";
        $sap = new saprfc(array(
                        "logindata"=>array(
                            "ASHOST"=>SAP_IP        // application server
                            ,"SYSNR"=>SAP_NR                // system number
                            ,"CLIENT"=>$client           // client
                            ,"LANG"=>"EN"
                            ,"USER"=>$randUser           // user
                            ,"PASSWD"=>$randPass       // password
                            //,"SAPROUTER"=>SAP_ROUTER
                            )
                        ,"show_errors"=>false           // let class printout errors
                        ,"debug"=>false)) ;                 // detailed debugging information
                            
 		$sap_result=$sap->callFunction("RFCPING", array());                             

        // Call successfull?
        if ($sap->getStatus() == SAPRFC_OK) {
            print_r($sap_result);
        } else { 
        // No, print long Version of last Error
            if($sap->getStatusText() == "NO ACCESS")
            {
                echo "The IP ".SAP_IP." is not valid. Script cancelled.\n";
                exit;
            }
            elseif($sap->getStatusText() != "WRONG CLIENT")
            {
                echo "Client ".$client." available.\n"; 
                $clients[$client] = $client;
                //if($sap->getStatusText() != "WRONG USER") echo $sap->getStatusText()."\n";
            }
        }
    
        // Logoff/Close saprfc-connection LL/2001-08
        $sap->logoff();        
    }        

    echo "\n-2- Discovering users\n\n";

    $success = array(); $warning = array();
    foreach($clients as $client)
    {
        foreach($wordlist as $user)
        {
            $sap = new saprfc(array(
                            "logindata"=>array(
                                "ASHOST"=>SAP_IP        // application server
                                ,"SYSNR"=>SAP_NR                // system number
                                ,"CLIENT"=>$client           // client
                                ,"LANG"=>"EN"
                                ,"USER"=>$user["user"]          // user
                                ,"PASSWD"=>$user["pass"]       // password
                                //,"SAPROUTER"=>SAP_ROUTER
                                )
                            ,"show_errors"=>false           // let class printout errors
                            ,"debug"=>false)) ;                 // detailed debugging information
                                
             $sap_result=$sap->callFunction("RFCPING", array());                             
    
            // Call successfull?
            if ($sap->getStatus() == SAPRFC_OK) {
                $success[$client][$user["user"]] = $user["pass"];
            } else { 
                if(substr($sap->getStatusText(),0,29) != "Name or password is incorrect") $warning[$client][$user["user"]] = array("message" => $sap->getStatusText(), "pass" => $user["pass"]);
                    //echo "User ".$user["user"]." Password ".$user["pass"]." - ".$sap->getStatusText()."\n";
            }
        
            // Logoff/Close saprfc-connection LL/2001-08
            $sap->logoff();                       
        }
    }

    if(sizeof($success) != 0) echo "Users accessible: \n\n";

    foreach($success as $client => $line)
    {
        foreach($line as $user => $pass)
        {
            echo " - Client: ".$client." Username: ".$user." Password: ".$pass."\n";
        } 
    }

    if(sizeof($warning) != 0) echo "\nUsers existing but not fully accessible: \n\n";
    
    foreach($warning as $client => $line)
    {
        foreach($line as $user => $info)
        {
            echo " - Client: ".$client." Username: ".$user." Password: ".$info["pass"]." - ".$info["message"]."\n";
        }
    }

    echo "\n-3- Discovering access level of reachable users\n\n";

    foreach($success as $client => $line)
    {
        foreach($line as $user => $pass)
        {
            $sap = new saprfc(array(
                "logindata"=>array(
                    "ASHOST"=>SAP_IP        // application server
                    ,"SYSNR"=>SAP_NR                // system number
                    ,"CLIENT"=>$client           // client
                    ,"LANG"=>"EN"
                    ,"USER"=>$user         // user
                    ,"PASSWD"=>$pass      // password
                    //,"SAPROUTER"=>SAP_ROUTER
                    )
                ,"show_errors"=>false           // let class printout errors
                ,"debug"=>false)) ;                 // detailed debugging information
                    
            $sap_result=$sap->callFunction("SUSR_USER_AUTH_FOR_OBJ_GET", array(array("IMPORT","USER_NAME",$user),array("IMPORT","SEL_OBJECT","S_TCODE")));   
            $sap_all = false;                           
            foreach($sap_result["VALUES"] as $reg)
            {   
                if(trim($reg["AUTH"]) == "&_SAP_ALL" || trim($reg["AUTH"]) == "S_TCD_ALL") $sap_all = true;
            }
            if($sap_all == true) echo "The user ".$user." in client ".$client." has powerful permissions (probably SAP_ALL)\n";

            $sap_result=$sap->callFunction("AUTHORITY_CHECK", array( array("IMPORT","USER", $user), array("IMPORT","OBJECT","S_TCODE"), array("IMPORT","FIELD1","TCD"), array("IMPORT","VALUE1","SU01")));   
            
            $auth = explode("key: ",$sap->getStatusText());

            if(trim($auth[1]) == "USER_IS_AUTHORIZED") echo "The user ".$user." in client ".$client." seems authorized to create and maintain users\n";

        }
    }

?>