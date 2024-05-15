#!/bin/bash

if [ "$1" = "release" ]; then
     trunk build --release
    cp ./docs/index.html ./docs/404.html
elif [ "$1" = "dev" ]; then
    trunk serve --open --public-url / --port=1334
else
    echo "Invalid argument. Please use 'release' or 'dev'."
fi
