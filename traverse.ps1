$filterString = "*.123,*.3dm,*.3ds,*.3g2,*.3gp,*.602,*.7z,*.ARC,*.PAQ,*.accdb,*.aes,*.ai,*.asc,*.asf,*.asm,*.asp,*.avi,*.backup,*.bak,*.bat,*.bmp,*.brd,*.bz2,*.cgm,*.class,*.cmd,*.cpp,*.crt,*.cs,*.csr,*.csv,*.db,*.dbf,*.dch,*.der,*.dif,*.dip,*.djvu,*.doc,*.docb,*.docm,*.docx,*.dot,*.dotm,*.dotx,*.dwg,*.edb,*.eml,*.fla,*.flv,*.frm,*.gif,*.gpg,*.gz,*.hwp,*.ibd,*.iso,*.jar,*.java,*.jpeg,*.jpg,*.js,*.jsp,*.key,*.lay,*.lay6,*.ldf,*.m3u,*.m4u,*.max,*.mdb,*.mdf,*.mid,*.mkv,*.mml,*.mov,*.mp3,*.mp4,*.mpeg,*.mpg,*.msg,*.myd,*.myi,*.nef,*.odb,*.odg,*.odp,*.ods,*.odt,*.onetoc2,*.ost,*.otg,*.otp,*.ots,*.ott,*.p12,*.pas,*.pdf,*.pem,*.pfx,*.php,*.pl,*.png,*.pot,*.potm,*.potx,*.ppam,*.pps,*.ppsm,*.ppsx,*.ppt,*.pptm,*.pptx,*.ps1,*.psd,*.pst,*.rar,*.raw,*.rb,*.rtf,*.sch,*.sh,*.sldm,*.sldx,*.slk,*.sln,*.snt,*.sql,*.sqlite3,*.sqlitedb,*.stc,*.std,*.sti,*.stw,*.suo,*.svg,*.swf,*.sxc,*.sxd,*.sxi,*.sxm,*.sxw,*.tar,*.tbk,*.tgz,*.tif,*.tiff,*.txt,*.uop,*.uot,*.vb,*.vbs,*.vcd,*.vdi,*.vmdk,*.vmx,*.vob,*.vsd,*.vsdx,*.wav,*.wb2,*.wk1,*.wks,*.wma,*.wmv,*.xlc,*.xlm,*.xls,*.xlsb,*.xlsm,*.xlsx,*.xlt,*.xltm,*.xltx,*.xlw,*.zip,*.lnk"
$filters = $filterString -split (",")
$exFilters = "^C:\\Windows*||^C:\\Users*"
# variables used in test
# $filters = "*.docx", "*.txt"
$outFile = "$HOME\Desktop\test.txt"

#http://jongurgul.com/blog/get-stringhash-get-filehash/ 
Function Get-StringHash([String] $String, $HashName = "MD5") { 
    $StringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | % { 
        [Void]$StringBuilder.Append($_.ToString("x2")) 
    } 
    $StringBuilder.ToString() 
}

function GetFilePrefix {
    Get-StringHash (Get-Date).ToString()
}
function isFile {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )
    try {
        (Get-Item -LiteralPath $FilePath -Force ) -is [System.IO.FileInfo]

    }
    catch {
        $False
    }
}
function GetFileAttributes {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath,
        [switch]
        $Link 
    )
   
    try {

        if (-not $Link) {
            $targetPath = $FilePath
        }
        else {
            $targetPath = (New-Object -ComObject WScript.Shell).CreateShortcut($FilePath).TargetPath
        }

        if ((Test-Path -Path $targetPath) -and (isFile -FilePath $targetPath) ) {
            $FileInfo = Get-Item -LiteralPath $targetPath -Force
            $FileInfo.Name,
            $FileInfo.Directory.FullName,
            $FileInfo.Length,
            $FileInfo.CreationTimeUtc.Ticks, 
            $FileInfo.LastAccessTimeUtc.Ticks, 
            $FileInfo.LastWriteTimeUtc.Ticks -join "|"
        }
    }
    catch {
        ""
    }
}
function GetDrives {
    try {
        Get-PSDrive -PSProvider FileSystem | 
        ForEach-Object { 
            if ( $_.Name -ne "C" -and $_.Used -ne 0 -and $_.Name.Length -eq 1) { $_.Root } 
        }
    }
    catch {
        Write-Host "Error: "
        Write-Host $_
    }
}

function GetUsersHome {
    try {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            $profile = Get-WmiObject Win32_UserProfile
        }
        else {
            $profile = Get-CimInstance Win32_UserProfile
        }

        $profile | 
        ForEach-Object { if ($_.Special -eq $False) { $_.Localpath } }
    }
    catch {
        Write-Host "Error: " $_
    }
}
function TraverseDirectory {
    param (
        # target path to traverse
        [Parameter(Mandatory = $true)]
        [String]
        $targetPath,
        [String]
        $outFile = $HOME + "\test.txt",
        [string[]]
        $Include,
        [String[]]
        $Exclude
    )


    if ($targetPath.EndsWith("\") -or $targetPath.EndsWith("/")) {
        $targetPath += "*"
    }
    else {
        $targetPath += "\*"
    }

    try {
        Write-Host "Target path: "  $targetPath  "`t-- traversing..."

        $stream = New-Object -TypeName System.IO.StreamWriter $outFile, $true

        Get-ChildItem -Path $targetPath -Include $filters -Recurse |
        Where-Object {
            (-Not $_.PsIsContainer)  # only file, no directory
            # (-Not ($_.FullName -match $exFilters )) # no file in C:\windows or C:\users
        } |
        ForEach-Object {
            try {

                # for shortcut file
                if ($_.Name.EndsWith((".lnk"))) {
                    $entry = GetFileAttributes -FilePath $_.FullName -Link
                }
                # for normal file
                else {
                    $entry = $_.Name, $_.Directory.FullName, $_.CreationTimeUtc.Ticks, $_.LastWriteTimeUtc.Ticks, $_.LastAccessTimeUtc.Ticks -join "|"
                }
                if ($entry.Length -gt 0) {
                    $stream.WriteLine($entry )
                }
            }
            catch {
                Write-Host "Error: " 
                Write-Host $_  
            }
        } 
    }
    catch {
        Write-Host "Error: "
        Write-Host $_
    }
    finally {
        $stream.Close()
    }
}

function TraverseMRURegistry {
    # test if Office installed
    $officeRootPath = "HKCU:\Software\Microsoft\Office"
    if ( Test-Path -Path $officeRootPath) {
        Get-ChildItem $officeRootPath | 
        Where-Object {
            # valid office version
            Test-Path -Path ($_.PSPath + "\Word\User MRU")
        } |
        ForEach-Object {
            try {
                $stream = New-Object -TypeName System.IO.StreamWriter $mruOutFile, $true

                Get-ChildItem -LiteralPath $_.PSPath | 
                Where-Object {
                    $MRUPath = $_.PSPath + "\User MRU"
                    (Test-Path -Path $MRUPath) -and ((Get-Item -LiteralPath $MRUPath).SubkeyCount -gt 0)
                } | 
                ForEach-Object {
                    # the software has MRU key
                    # path: Software\Microsoft\Office\16.0\Access\User MRU\LiveId_753E9B29030F87D58CD2B6B24281D2B2823B39E31952537828A017C278FD4D4B\File MRU
                    $MRUPath = (Get-ChildItem -LiteralPath ($MRUPath))[0].PSPath + "\File MRU"
                    Get-Item -LiteralPath $MRUPath | Select-Object -ExpandProperty property | 
                    ForEach-Object { 
                        $path = (Get-ItemProperty -LiteralPath $MRUPath -Name $_).$_ 
                        $path = $path -creplace '^(\[.*?\]){3}\*' , ''
                        $entry = GetFileAttributes -FilePath $path
                        if ($entry.Length -gt 0) {
                            $stream.WriteLine($entry)
                        }
                    }
                }
            }
            catch {
                Write-Host "Error: " $_
            }
            finally {
                $stream.Close()
            }
        }
    }
}

function TraverseMRUFolder {
    $MRUFolderSuffix = "\AppData\Roaming\Microsoft\Windows\Recent"
    GetUsersHome | 
    Where-Object {
        Test-Path -Path ($_ + $MRUFolderSuffix)
    } |
    ForEach-Object {
        TraverseDirectory -targetPath ($_ + $MRUFolderSuffix) -outFile $mruOutFile
    }
}

function TraverseMRU {
    TraverseMRUFolder
    TraverseMRURegistry
}

function TraverseUserHome {
    GetUsersHome | ForEach-Object { TraverseDirectory -targetPath $_ -outFile $userOutFile }
}
function TraverseDisk {
    # traverse C:\ , except C:\windows and C:\users
    # Get-ChildItem "C:\*" -Exclude "Windows*", "Users*" | ForEach-Object { TraverseDirectory -targetPath $_.FullName -outFile $diskOutFile }

    Get-ChildItem "C:\" |
    Where-Object {
        (-Not $_.FullName.StartsWith("C:\Windows")) -and
        (-Not $_.FullName.StartsWith("C:\Users"))
    } | 
    ForEach-Object {
        if ($_.PsIsContainer) {
            TraverseDirectory -targetPath $_.FullName -outFile $diskOutFile 
        }
        else {
            $entry = $_.Name, $_.Directory.FullName, $_.CreationTimeUtc.Ticks, $_.LastWriteTimeUtc.Ticks, $_.LastAccessTimeUtc.Ticks -join "|"
            Out-File -FilePath $diskOutFile -Append -InputObject $entry
        }
    }

    # traverse other disks
    GetDrives | ForEach-Object { TraverseDirectory -targetPath $_ -outFile $diskOutFile }
}
function MainTraverse {
    [CmdletBinding()]
    param (
        # Traverse all disks except C:\
        [Boolean]
        $Disk = $True,
        # Traverse all users's home directory
        [Boolean]
        $User = $True,
        # Traverse software MRU registry and folder
        [Boolean]
        $MRU = $True
    )

    if ($Disk) {
        TraverseDisk
    }

    if ($User) {
        TraverseUserHome
    }

    if ($MRU) {
        TraverseMRU
    }

}

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$filePrefix = GetFilePrefix
$diskOutFile = $scriptPath + "\" + $filePrefix + "_disk.csv"
$userOutFile = $scriptPath + "\" + $filePrefix + "_user.csv"
$mruOutFile = $scriptPath + "\" + $filePrefix + "_mru.csv"

# $targetPath = "$HOME\*"
MainTraverse 
# GetFilePrefix
# TraverseDirectory -targetPath "c:\windows"
# TraverseDirectory -targetPath $targetPath
# MainTraverse
# GetUsersHome
# TraverseMRU
# TraverseMRURegistry
# TraverseMRUFolder
# TraverseDisk
# TraverseUserHome
# Get-ChildItem . -File | % {GetFileAttributes $_}
# GetFileAttributes -FilePath "C:\Users\MOUKA\Documents\Tencent Files\546414028\FileRecv\2017-2018（一）全日制硕士公共课课表.xls"
# GetFileAttributes -FilePath "C:\Users\MOUKA\AppData\Roaming\Microsoft\Windows\Recent\change.log.lnk" -Link

