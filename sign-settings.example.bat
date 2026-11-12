@echo off
rem Copy this file to sign-settings.bat and fill in ONE of the two options.
rem sign-settings.bat stays on the build PC. It holds no secret, but it is not part of the kit.

rem OPTION 1: a certificate on a USB token or in the Windows certificate store
rem   Plug in the token, open certmgr.msc > Personal > Certificates > open the code-signing
rem   certificate > Details > Thumbprint. Paste it here without spaces.
set "SIGN_THUMBPRINT="

rem OPTION 2: Microsoft Azure Artifact Signing (formerly Trusted Signing)
rem   SIGN_DLIB     = full path of Azure.CodeSigning.Dlib.dll (from the Artifact Signing client tools)
rem   SIGN_METADATA = full path of your metadata.json (endpoint, account name, certificate profile)
rem   Sign in first with:  az login
set "SIGN_DLIB="
set "SIGN_METADATA="
rem   Artifact Signing has its own timestamp server:
rem set "SIGN_TIMESTAMP=http://timestamp.acs.microsoft.com"
