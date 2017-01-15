Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install -y cmder
choco install -y git.install

choco install -y vcredist2005 > nul
choco install -y vcredist2008 > nul
choco install -y vcredist2010 > nul
choco install -y vcredist2012 > nul
choco install -y vcredist2013 > nul
choco install -y vcredist2015 > nul
choco install -y googlechrome > nul
choco install -y dotnet3.5 > nul
choco install -y dotnet4.5.2 > nul
choco install -y dotnet4.6.1 > nul
choco install -y 7zip.commandline > nul
choco install -y curl > nul
choco install -y git > nul
choco install -y python2 > nul
choco install -y sysinternals > nul
choco install -y wget > nul
choco install -y lastpass > nul
choco install -y unxutils > nul
choco install -y windows-sdk-8.1 > nul
choco install -y windows-sdk-10.1 > nul
choco install -y windbg > nul
