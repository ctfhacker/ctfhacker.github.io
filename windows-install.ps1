Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install -y cmder
choco install -y git.install

choco install -y vcredist2005
choco install -y vcredist2008
choco install -y vcredist2010
choco install -y vcredist2012
choco install -y vcredist2013
choco install -y vcredist2015
choco install -y googlechrome
choco install -y dotnet3.5
choco install -y dotnet4.5.2
choco install -y dotnet4.6.1
choco install -y 7zip.commandline
choco install -y curl
choco install -y git
choco install -y python2
choco install -y sysinternals
choco install -y wget
choco install -y lastpass
choco install -y unxutils
choco install -y windows-sdk-8.1
choco install -y windows-sdk-10.1
choco install -y windbg
