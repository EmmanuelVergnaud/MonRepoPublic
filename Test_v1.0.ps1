# Purpose of this script:
# This script download the latest zip release of Chrome (x86 or x64, according the arch of the machine),
# extract the Zip files, verify the digital signature of all the MSI files in the archive,
# push the `SignerCertificate` of the all the *valid* signature to Github (using gist)
# and finally return the url of the gist.
# I could have added the creation of a log file, but I didn't want to make the script too heavy.
# Author: Emmanuel Vergnaud (with a 'little' help from Google)
# Version 1.0.0


#------------- Download the last zip release of Chrome -------------

# Get Processor Architecture and set url for download
$Architecture = Get-WmiObject -class win32_processor -ComputerName "." | Where-Object {$_.DeviceID -eq "CPU0"}
Switch ($architecture.AddressWidth)
	{
		"32" {$ProcArch = "86"; $uriNewChromeURL = 'https://dl.google.com/dl/chrome/install/GoogleChromeEnterpriseBundle.zip'}
		default {$ProcArch = "64"; $uriNewChromeURL = 'https://dl.google.com/dl/chrome/install/GoogleChromeEnterpriseBundle64.zip'}
	}


$strChromeDownloadFolder = $env:TEMP
$strChromeSaveAsName = 'GoogleChromeEnterpriseBundle' + $ProcArch + '.zip'

# Download Chrome zip
Function Download-ChromeZIP{
    Param([uri]$ChromeDownloadPath,[string]$ChromeDownloadFolder,[string]$ChromeSaveAsName)
    If(!(Test-Path $ChromeDownloadFolder)){
        mkdir $ChromeDownloadFolder
    }
    $objWebRequest = Invoke-WebRequest $ChromeDownloadPath -outfile (Join-Path $ChromeDownloadFolder -childpath $strChromeSaveAsName)
}

Download-ChromeZIP -ChromeDownloadPath $uriNewChromeURL -ChromeDownloadFolder $strChromeDownloadFolder -ChromeSaveAsName $strChromeSaveAsName

#------------- End of download -------------



#------------- Unzip files -------------

$UnzipedChromeFolderPath = (Join-Path $strChromeDownloadFolder -childpath $("GoogleChromeEnterpriseBundle" + $ProcArch))
Expand-Archive -LiteralPath (Join-Path $strChromeDownloadFolder -childpath $strChromeSaveAsName) -DestinationPath $UnzipedChromeFolderPath -Force

#------------- End of Unzip files -------------



#------------- Get SignerCertificates for valid digital signature of MSI files -------------

$MsiCheckResult = Get-ChildItem -Path $UnzipedChromeFolderPath -Recurse -File | where {$_.extension -eq ".msi"} | ForEach-object {Get-AuthenticodeSignature $_.FullName}

# Save all the SignerCertificates in the variable $GistsText
foreach ($Msi in $MsiCheckResult){
    if ($Msi.status -eq "Valid") {
	$GistsText += $Msi.SignerCertificate.toString()
	   }
}

#------------- End of get SignerCertificates -------------



#------------- Post result on Gists and return the url -------------

$BaseUri = $Uri = 'https://api.github.com/gists'    
$Method  = 'POST'

# Gist formatting
$JSON = ConvertTo-Json @{
		description = "Chrome MSI SignerCertificate";
		public = $true;
		files = @{
		  "Chrome_MSI_SignerCertificate.txt" = @{
			content = $GistsText
			}
	  	}
	}


# Authentication management
function Get-GistAuthHeader {

    if(!$Global:GitHubCred) { $Global:GitHubCred = Get-Credential ''}

    $authInfo = "{0}:{1}" -f $Global:GitHubCred.UserName, $Global:GitHubCred.GetNetworkCredential().Password
    $authInfo = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($authInfo))

    @{
        'Authorization' = 'Basic ' + $authInfo
        'Content-Type' = 'application/json'
    }
}

$Header = Get-GistAuthHeader 

# Upload Gist
$resp = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Header -Body $JSON


# Return the url of the gist
#Start-Process $resp.'html_url'
$resp.'html_url'

#------------- End of Post -------------


#------------- Clean up (just a suggestion) -------------
<#
Remove-Item (Join-Path $strChromeDownloadFolder -childpath $strChromeSaveAsName)
Remove-Item $UnzipedChromeFolderPath -Recurse
#>
#------------- End of Clean up ------------
