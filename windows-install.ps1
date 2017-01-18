Write-Host "Installing chocolatey"
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Write-Host "Installing git"
choco install -y git.install

((New-Object System.Net.WebClient).DownloadFile('https://github.com/ctfhacker/windows-setup/archive/master.zip', 'C:\Windows\Temp\master.zip'))

cd C:\Windows\Temp\
[System.IO.Compression.ZipFile]::ExtractToDirectory('master.zip', 'windows-setup')
cd windows-setup

Get-ChildItem | ForEach-Object {
    Write-Host "Executing " + $_.FullName
    & $_.FullName
}

Write-Host "Rebooting.."
shutdown /r /t 0
