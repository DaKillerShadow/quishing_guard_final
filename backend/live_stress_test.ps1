$baseUrl = "https://quishing-guard-backend.onrender.com/api/v1/analyse"

$scenarios = @(
    # 1. Network & Routing (Redirects, Shorteners, SSRF)
    @{ name = "The Daisy Chain (Nested/Depth)"; url = "https://j.mp/3V3n9R1" }, # Public shortener chain
    @{ name = "SSRF Protection (Internal Block)"; url = "http://169.254.169.254/metadata" }, # Cloud Metadata IP

    # 2. Domain Anatomy (IP, Punycode, DGA, TLD, Subdomains)
    @{ name = "The Punycode Impersonator"; url = "https://xn--pple-43d.com/login" },
    @{ name = "The DGA Botnet Link"; url = "https://x7z9q2mwpb.ru/update/secure" },
    @{ name = "The Raw IP Payload"; url = "http://142.250.190.46/verify" },
    @{ name = "The Deep Subdomain Nest"; url = "https://a.b.c.d.e.f.phish-site.net" }, # Use unranked domain

    # 3. Content & Protocol (Keywords, HTTPS, Evasion)
    @{ name = "HTTPS Enforcement & TLD"; url = "http://fawry-pay.info/login" },
    @{ name = "The Reputation Shield (Trust Test)"; url = "https://apple.com/login" }
)

Write-Host "`n🚀 EXECUTING 11-PILLAR TOTAL STRESS TEST..." -ForegroundColor Cyan

foreach ($s in $scenarios) {
    Write-Host "--------------------------------------------------" -ForegroundColor Gray
    Write-Host "SCENARIO: $($s.name)" -ForegroundColor White
    
    try {
        $body = @{ url = $s.url } | ConvertTo-Json
        $response = Invoke-RestMethod -Method Post -Uri $baseUrl -ContentType "application/json" -Body $body
        
        $statusColor = "Red"; if ($response.risk_label -eq "safe") { $statusColor = "Green" }; if ($response.risk_label -eq "warning") { $statusColor = "Yellow" }
        Write-Host "STATUS:   $($response.risk_label.ToUpper()) ($($response.risk_score)/100)" -ForegroundColor $statusColor

        $triggered = $response.checks | Where-Object { $_.triggered -eq $true }
        Write-Host "TRIGGERED:" -ForegroundColor Yellow
        foreach ($p in $triggered) {
            Write-Host "  [!] $($p.label) (+$($p.score) pts)"
        }
    } catch {
        Write-Host "  [!] ERROR/BLOCKED: $($_.Exception.Message)" -ForegroundColor Gray
    }
}