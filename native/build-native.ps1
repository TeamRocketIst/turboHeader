param([string]$BuildDir = "$PSScriptRoot/build")
$ErrorActionPreference = "Stop"
cmake -S $PSScriptRoot -B $BuildDir -DCMAKE_BUILD_TYPE=Release
cmake --build $BuildDir --config Release --parallel
