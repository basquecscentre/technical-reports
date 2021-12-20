rule RedLine
{
	strings:
		$mz = {4D 5A}
		$s1 = "IRemoteEndpoint"
		$s2 = "ITaskProcessor"
		$s3 = "ScannedFile"
		$s4 = "ScanningArgs"
		$s5 = "ScanResult"
		$s6 = "DownloadAndExecuteUpdate"
		$s7 = "OpenUpdate"
		$s8 = "CommandLineUpdate"
		$s9 = "TryCompleteTask"
		$s10 = "TryGetTasks"
		$s11 = "TryInitBrowsers"
		$s12 = "InstalledBrowsers"
		$s13 = "TryInitInstalledBrowsers"
		$s14 = "TryInitInstalledSoftwares"
		$s15 = "TryGetConnection"

	condition:
	($mz at 0) and (10 of ($s*))
}