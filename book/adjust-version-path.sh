#!/bin/bash

set -e
shopt -s globstar

pushd "versioned_docs/version-$1"

if [[ $OSTYPE == "darwin"* ]]; then
    # Mac OS X
    sed -i '' 's|\.\.\/\.\.\/static|..\/..\/..\/static|g' **/*.md
    sed -i '' 's|\.\.\/\.\.\/static|..\/..\/..\/static|g' **/*.mdx
else
    # Other OSes
    sed -i 's|\.\.\/\.\.\/static|..\/..\/..\/static|g' **/*.md
    sed -i 's|\.\.\/\.\.\/static|..\/..\/..\/static|g' **/*.mdx
fi

popd
