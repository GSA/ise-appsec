#!/usr/bin/env bash

# Dependencies:
#  - JDK >= 17
#  - Build tools installed (e.g. Maven or Gradle)
#  - fcli.jar 
#  - scancentral executable

# Source Environment vars defined in external file:
# . .env

# Example .env file:
# export FCLI_DEFAULT_FOD_URL='https://fed.fortifygov.com' # Keep this as-is
# fod_app_name='GSA/ise-appsec'                           # Set this to your app name
# fod_release_name='test-release-1'                        # This can be the name of the branch
# fod_client_id=                                           # your client ID
# fod_client_secret=                                       # your client secret
# fcli_home=/path/to/fcli                                  # directory containing fcli.jar
# alias fcli='java -jar "${fcli_home}"/fcli.jar'           # Alias for convenience


# Authenticate with API Key Client Credentials
fcli fod session login --client-id="${fod_client_id}" --client-secret="${fod_client_secret}"

# Package 
scancentral package -o ../package.zip

# Create the release if it does not exist
fcli fod action run setup-release --rel "${fod_app_name}:${fod_release_name}" --scan-types sast --assessment-type "Static+"

# Scan
fcli fod sast-scan start --rel "${fod_app_name}:${fod_release_name}" -f ../package.zip --store fod_sast_scan

# Log out
fcli fod session logout