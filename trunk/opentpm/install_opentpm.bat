copy sys\opentpm.sys C:\windows\system32
sc create OpenTPM type= kernel start= auto binPath= C:\windows\system32\opentpm.sys
sc start OpenTPM
