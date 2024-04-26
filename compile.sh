#!/bin/bash

# Error checks
set -e

# Generate a configure script
if ! autoreconf --install; then
    echo "Error generating configure script"
    exit 1
fi

# Run configure
if ! ./configure; then
    echo "Error running configure"
    exit 1
fi

# Compile the library
if ! make; then
    echo "Error compiling the library"
    exit 1
fi

# Compile the test application
cd test_application/iotsec_server || {
    echo "Error changing directory to test_application/iotsec_server"
    exit 1
}

# Compile the test application
if ! make; then
    echo "Error compiling the test application in iotsec_server"
    exit 1
fi

cd ../ || {
    echo "Error changing directory to parent directory"
    exit 1
}

cd iotsec_client || {
    echo "Error changing directory to iotsec_client"
    exit 1
}

# Compile the test application
if ! make; then
    echo "Error compiling the test application in iotsec_client"
    exit 1
fi

cd ../../ || {
    echo "Error changing directory to parent directory"
    exit 1
}

# Generate documentation
if ! doxygen Doxyfile; then
    echo "Error generating documentation"
    exit 1
fi
