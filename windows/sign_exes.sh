#!/bin/bash

# read SIGNING_PASSWORD from pass password store
#eval $(pass signtool)

# add a small Powershell script helper as env
read -r -d '' SIGNTOOL <<'EOF'
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import('C:/certs/cert.p12', '', 'DefaultKeySet')
Set-AuthenticodeSignature -Cert $cert -TimeStampServer http://timestamp.verisign.com/scripts/timestamp.dll -FilePath $env:FILE
EOF
export SIGNTOOL

# run a Windows container to sign the exe/ps1 script
docker run --rm -v "/Users/jan/Spideroak Backup/Comodo code signing certificate.p12:/C/certs/cert.p12:ro" -v "$(pwd):/C/signing" -w /C/signing \
  -e SIGNING_PASSWORD -e SIGNTOOL -e FILE=$1 mcr.microsoft.com/windows/servercore:ltsc2019 \
  powershell -command iex\(\$env:SIGNTOOL\)