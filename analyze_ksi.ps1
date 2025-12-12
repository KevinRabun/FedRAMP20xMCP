# Check KSI-SVC-01, KSI-SVC-02, KSI-MLA-01, KSI-MLA-02, KSI-IAM-06, KSI-CNA-07
$ksis = @("ksi_svc_01", "ksi_svc_02", "ksi_mla_01", "ksi_mla_02", "ksi_iam_06", "ksi_cna_07")

foreach ($ksi in $ksis) {
    $file = "src/fedramp_20x_mcp/analyzers/ksi/$ksi.py"
    if (Test-Path $file) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "FILE: $ksi" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        # Extract class docstring and analyze method
        $content = Get-Content $file -Raw
        if ($content -match '"""([^"]+)"""') {
            Write-Host "`nDESCRIPTION:" -ForegroundColor Yellow
            Write-Host $matches[1].Trim()
        }
        
        # Look for detection patterns
        if ($content -match 'def analyze\(self[^{]+\{([^}]+)\}') {
            Write-Host "`nKEY DETECTION LOGIC:" -ForegroundColor Yellow
            $content | Select-String -Pattern "(networkAcls|defaultAction|Key Vault|keyVaultProperties|encryption|diagnosticSettings|logs|retentionPolicy|identity|principalId|policyAssignments)" -Context 0,1 | Select-Object -First 5 | ForEach-Object { Write-Host "  - $_" }
        }
    }
}
