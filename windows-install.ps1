Write-Host "Installing chocolatey"
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

((New-Object System.Net.WebClient).DownloadFile('https://github.com/ctfhacker/windows-setup/archive/master.zip', 'C:\Windows\Temp\master.zip'))

cd C:\Windows\Temp\
mkdir master
$shell = new-object -com shell.application
$zip = $shell.NameSpace("C:\Windows\Temp\master.zip")
foreach($item in $zip.items())
{
    $shell.Namespace(".\master").copyhere($item)
}

cd master\windows-setup-master

Get-ChildItem | ForEach-Object {
    Write-Host "Executing " + $_.FullName
    & $_.FullName
}

Write-Host "Rebooting.."
shutdown /r /t 0
