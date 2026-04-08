$baseUrl = "http://localhost:5000/api/v1/analyse"

# 🛑 REPLACE THIS with your Layer 2 link
$nestedUrl = "https://bit.ly/short-link-gcg" 

Write-Host "`n--- Testing Nested Shortener Trap ---" -ForegroundColor Cyan

$body = @{ url = $nestedUrl } | ConvertTo-Json
$response = Invoke-RestMethod -Method Post -Uri $baseUrl -ContentType "application/json" -Body $body

Write-Host "Risk Score: $($response.risk_score)"
Write-Host "Label: $($response.risk_label.ToUpper())"
Write-Host "Total Hops Followed: $($response.hop_count)"
Write-Host "Final Destination: $($response.resolved_url)"

Write-Host "`nTriggered Pillars:"
foreach ($check in $response.checks) {
    if ($check.triggered) {
        Write-Host "  [!] $($check.label) (+$($check.score) pts)" -ForegroundColor Yellow
    }
}