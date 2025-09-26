@echo off
echo Fixing BLE libraries...

REM Fix react-native-ble-peripheral
powershell -Command "(Get-Content 'node_modules\react-native-ble-peripheral\android\build.gradle') -replace 'compileSdkVersion \d+', 'compileSdkVersion 33' -replace 'targetSdkVersion \d+', 'targetSdkVersion 33' -replace 'buildToolsVersion .*', '' -replace 'compile ', 'implementation ' -replace 'com.android.support:appcompat-v7:.*\"', 'androidx.appcompat:appcompat:1.3.1\"' | Set-Content 'node_modules\react-native-ble-peripheral\android\build.gradle'"

REM Add compileOptions if missing
powershell -Command "$content = Get-Content 'node_modules\react-native-ble-peripheral\android\build.gradle' -Raw; if ($content -notmatch 'compileOptions') { $content = $content -replace '(defaultConfig \{[^}]*\})', '$1`n    compileOptions {`n        sourceCompatibility JavaVersion.VERSION_11`n        targetCompatibility JavaVersion.VERSION_11`n    }' }; $content | Set-Content 'node_modules\react-native-ble-peripheral\android\build.gradle'"

echo Fixed react-native-ble-peripheral

REM Fix other BLE libraries if they exist
if exist "node_modules\react-native-ble-advertiser\android\build.gradle" (
    powershell -Command "(Get-Content 'node_modules\react-native-ble-advertiser\android\build.gradle') -replace 'compileSdkVersion \d+', 'compileSdkVersion 33' -replace 'targetSdkVersion \d+', 'targetSdkVersion 33' -replace 'buildToolsVersion .*', '' -replace 'compile ', 'implementation ' | Set-Content 'node_modules\react-native-ble-advertiser\android\build.gradle'"
    echo Fixed react-native-ble-advertiser
)

if exist "node_modules\react-native-ble-manager\android\build.gradle" (
    powershell -Command "(Get-Content 'node_modules\react-native-ble-manager\android\build.gradle') -replace 'compileSdkVersion \d+', 'compileSdkVersion 33' -replace 'targetSdkVersion \d+', 'targetSdkVersion 33' -replace 'buildToolsVersion .*', '' -replace 'compile ', 'implementation ' | Set-Content 'node_modules\react-native-ble-manager\android\build.gradle'"
    echo Fixed react-native-ble-manager
)

echo All BLE libraries fixed!