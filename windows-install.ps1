Write-Host "Installing chocolatey"
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install -y git

cd C:\Windows\Temp\
& "C:\Program Files\Git\bin\git.exe" clone https://github.com/ctfhacker/windows-setup
cd windows-setup

Get-ChildItem -exclude pykd* | ForEach-Object {
    Write-Host "Executing " + $_.FullName
    & $_.FullName
}
