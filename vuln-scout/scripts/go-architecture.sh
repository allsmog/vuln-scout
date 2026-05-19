#!/bin/bash
# go-architecture.sh - Generate architecture-focused scope for Go codebases
#
# Usage: ./go-architecture.sh [target-path] [output-file]
#
# This script creates a compressed architecture view of a Go codebase by:
# 1. Extracting key architecture files (interfaces, handlers, types, services)
# 2. Generating API documentation using go doc
# 3. Combining into a single scope file optimized for threat modeling

set -e

TARGET=${1:-.}
OUTPUT=${2:-.claude/scope-architecture.md}
TEMP_DIR=$(mktemp -d)

echo "Generating Go architecture scope for: $TARGET"
echo "Output: $OUTPUT"

# Ensure .claude directory exists
mkdir -p "$(dirname "$OUTPUT")"

# Start the scope file
cat > "$OUTPUT" << 'EOF'
# Go Architecture Scope

This is a compressed architecture view of the codebase, optimized for:
- Threat modeling
- Trust boundary identification
- Component inventory
- Data flow analysis

**Note**: This view excludes implementation details. For detailed vulnerability hunting, scope individual modules.

EOF

echo "Generated: $(date)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Section 1: Module Structure
echo "## Module Structure" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo '```' >> "$OUTPUT"
if [ -f "$TARGET/go.mod" ]; then
    head -20 "$TARGET/go.mod" >> "$OUTPUT" 2>/dev/null || echo "go.mod not readable"
fi
echo '```' >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Section 2: Package List
echo "## Packages" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo '```' >> "$OUTPUT"
(cd "$TARGET" && go list ./... 2>/dev/null | head -100) >> "$OUTPUT" || echo "Could not list packages"
echo '```' >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Section 3: Key Architecture Files
echo "## Key Architecture Files" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Find and list interface files
echo "### Interface Definitions" >> "$OUTPUT"
echo "" >> "$OUTPUT"
find "$TARGET" -name "*interface*.go" -o -name "*Interface*.go" 2>/dev/null | grep -v "_test.go" | head -20 | while read -r file; do
    if [ -f "$file" ]; then
        echo "#### $file" >> "$OUTPUT"
        echo '```go' >> "$OUTPUT"
        grep -A 5 "^type.*interface" "$file" 2>/dev/null | head -50 >> "$OUTPUT" || true
        echo '```' >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi
done

# Find handler files
echo "### Handlers" >> "$OUTPUT"
echo "" >> "$OUTPUT"
find "$TARGET" -name "*handler*.go" -o -name "*Handler*.go" 2>/dev/null | grep -v "_test.go" | head -20 | while read -r file; do
    if [ -f "$file" ]; then
        echo "- $file" >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

# Find service files
echo "### Services" >> "$OUTPUT"
echo "" >> "$OUTPUT"
find "$TARGET" -name "*service*.go" -o -name "*Service*.go" 2>/dev/null | grep -v "_test.go" | head -20 | while read -r file; do
    if [ -f "$file" ]; then
        echo "- $file" >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

# Section 4: API Documentation
echo "## Public API Documentation" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Extracted using \`go doc -all\`:" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo '```' >> "$OUTPUT"
(cd "$TARGET" && go doc -all ./... 2>/dev/null | head -10000) >> "$OUTPUT" || echo "Could not generate go doc"
echo '```' >> "$OUTPUT"

# Cleanup
rm -rf "$TEMP_DIR"

# Report results
echo ""
echo "Architecture scope generated successfully!"
echo "Output: $OUTPUT"
echo "Size: $(wc -l < "$OUTPUT") lines"

# Estimate tokens (rough: ~4 chars per token)
chars=$(wc -c < "$OUTPUT" | tr -d ' ')
tokens=$((chars / 4))
echo "Estimated tokens: ~$tokens"
