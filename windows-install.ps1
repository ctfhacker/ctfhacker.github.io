Write-Host "Installing chocolatey"
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Write-Host "Installing unzip"
choco install -y unzip

((New-Object System.Net.WebClient).DownloadFile('https://github.com/ctfhacker/windows-setup/archive/master.zip', 'C:\Windows\Temp\master.zip'))

cd C:\Windows\Temp\
unzip master.zip
cd windows-setup-master

Get-ChildItem | ForEach-Object {
    Write-Host "Executing " + $_.FullName
    & $_.FullName
}

# Write-Host "Rebooting.."
# shutdown /r /t 0
