choco install -y virtualclonedrive
Write-Host "Downloading VS2010Express.iso" -foregroundcolor "Green" -backgroundcolor "Black"
((new-object system.net.webclient).downloadfile('http://download.microsoft.com/download/1/E/5/1E5F1C0A-0D5B-426A-A603-1798B951DDAE/VS2010Express1.iso', 'C:\Windows\Temp\VS2010Express.iso'))
