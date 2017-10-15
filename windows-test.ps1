if(-Not (Get-Command choco -errorAction SilentlyContinue)){
    iex ((new-object system.net.webclient).downloadstring('https://chocolatey.org/install.ps1'))
}
choco install -y virtualclonedrive
Write-Host "Downloading VS2010Express.iso" -foregroundcolor "Green" -backgroundcolor "Black"
((new-object system.net.webclient).downloadfile('http://download.microsoft.com/download/1/E/5/1E5F1C0A-0D5B-426A-A603-1798B951DDAE/VS2010Express1.iso', 'C:\Windows\Temp\VS2010Express.iso'))
Write-Host "Mounting VS2010Express.iso" -foregroundcolor "Green" -backgroundcolor "Black"
& "C:\Program Files\Elaborate Bytes\VirtualCloneDrive\VCDMount.exe" /l=E C:\Windows\Temp\VS2010Express.iso
Write-Host "Installing VS2010Express.iso" -foregroundcolor "Green" -backgroundcolor "Black"
& "E:\VCExpress\setup.exe" /q /norestart
Write-Host "Done Installing VS2010Express.iso" -foregroundcolor "Green" -backgroundcolor "Black"
choco uninstall -y virtualclonedrive
