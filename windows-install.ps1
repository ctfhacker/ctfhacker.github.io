Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install -y conemu
choco install -y msys2
