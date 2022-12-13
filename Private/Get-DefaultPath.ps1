function Get-DefaultPath {
    [CmdletBinding()]
    [OutPutType([System.String])]
    Param()
    Process {
        $homePath = if ($HOME) { $HOME } elseif (Test-Path "~") { (Resolve-Path "~").Path }
        $DefaultP = [System.IO.Path]::Combine($homePath, ".ssh", "id_rsa")
    }
    end {
        return $DefaultP
    }
}
