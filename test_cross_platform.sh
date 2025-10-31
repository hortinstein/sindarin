#!/bin/bash
# Cross-platform interoperability test for Sindarin
# Tests Python → C binary compatibility

set -e

echo "========================================================================"
echo "Sindarin Cross-Platform Interoperability Test"
echo "Testing: Python → C Binary Compatibility"
echo "========================================================================"
echo ""

# Step 1: Generate Python config
echo "Step 1: Generating config with Python..."
echo "------------------------------------------------------------------------"
python3 generate_python_config.py
echo ""

# Step 2: Display the generated file
echo "Step 2: Examining generated file..."
echo "------------------------------------------------------------------------"
echo "File: python_generated.config"
ls -lh python_generated.config
echo ""
echo "Contents (base64):"
cat python_generated.config
echo ""
echo ""

# Step 3: Test with C
echo "Step 3: Reading config with C..."
echo "------------------------------------------------------------------------"
cd c_version
make test-python
cd ..
echo ""

# Step 4: Summary
echo "========================================================================"
echo "✓ Cross-Platform Test Complete!"
echo "========================================================================"
echo ""
echo "Summary:"
echo "  ✓ Python successfully generated EncConfig"
echo "  ✓ Python serialized to binary with Flatty"
echo "  ✓ Python encoded to URL-safe base64"
echo "  ✓ C successfully decoded base64"
echo "  ✓ C successfully deserialized EncConfig"
echo "  ✓ C successfully extracted StaticConfig"
echo ""
echo "Result: Binary format is FULLY COMPATIBLE between Python and C!"
echo "========================================================================"
