#!/bin/bash
# Comprehensive C/Python interoperability test script

set -e

echo "========================================="
echo "C/Python Interoperability Test Suite"
echo "========================================="
echo ""

# Build C code
echo "Step 1: Building C implementation..."
cd c_implementation
make clean
make all
echo "✓ C code built successfully"
echo ""

# Run C standalone tests
echo "Step 2: Running C standalone tests..."
echo "--- Encryption Tests ---"
./test_encryption
echo ""
echo "--- Serialization Tests ---"
./test_serialization
echo ""
echo "--- Roundtrip Test ---"
./test_roundtrip
echo "✓ C standalone tests passed"
echo ""

# Run C to Python test
echo "Step 3: C creates data for Python..."
./test_c_to_python
cd ..
echo "✓ C data files created"
echo ""

# Python reads C data
echo "Step 4: Python reads C data..."
python3 test_python_c_interop.py read
echo "✓ Python successfully read C data"
echo ""

# Python creates data for C
echo "Step 5: Python creates data for C..."
python3 test_python_c_interop.py create
echo "✓ Python data files created"
echo ""

# C reads Python data
echo "Step 6: C reads Python data..."
cd c_implementation
./test_python_to_c
cd ..
echo "✓ C successfully read Python data"
echo ""

echo "========================================="
echo "All interoperability tests PASSED!"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✓ C encryption/decryption working"
echo "  ✓ C serialization/deserialization working"
echo "  ✓ C ↔ Python encryption interoperability"
echo "  ✓ C ↔ Python serialization interoperability"
echo "  ✓ Full roundtrip encryption+serialization"
echo ""
