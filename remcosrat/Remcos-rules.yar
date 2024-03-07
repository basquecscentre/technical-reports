rule agente_remcos {
	meta:
		description = "Deteccion de la ejecución de un agente del RAT Remcos"
       		sharing = "TLP:WHITE"
	strings:
		$s1 = "Watchdog module activated" ascii
		$s2 = "Remcos restarted by watchdog!" ascii
		$s3 = " BreakingSecurity.net" ascii
	condition:
		//uint16(0) == 0x5a4d 
		//and
		(all of ($s*))
		
	}
