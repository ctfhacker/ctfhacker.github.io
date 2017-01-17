Write-Host "Installing chocolatey"
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Write-Host "Installing git"
choco install -y git.install

Write-Host "Cloning windows-setup"
git clone https://github.com/ctfhacker/windows-setup C:\Windows\Temp\windows-setup

cd C:\Windows\Temp\windows-setup
Get-ChildItem | ForEach-Object {
    Write-Host "Executing " + $_.FullName
    & $_.FullName
}
