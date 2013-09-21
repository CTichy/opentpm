tpmtakeown.exe -pwdo password
identity.exe -pwdo password -la identity
createkey.exe -hp 40000000 -ok signingkey

mkdir C:\tpm_keys
copy identity.key C:\tpm_keys
copy signingkey.key C:\tpm_keys
