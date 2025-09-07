#!/bin/bash

echo "Fixing remaining test issues..."

# Fix files that still use waitFor but have it removed from imports
find src -name "*.test.tsx" -o -name "*.test.ts" | while read file; do
    # Check if the file uses waitFor but doesn't import it
    if grep -q "waitFor(" "$file" && ! grep -q "import.*waitFor" "$file"; then
        echo "Adding waitFor import to $file"
        # Add waitFor to testing library import if it exists
        sed -i '' '/import.*render.*screen.*@testing-library\/react/s/screen/screen, waitFor/' "$file"
    fi
    
    # Fix jest-axe expect.extend type issues
    sed -i '' 's/expect\.extend({ toHaveNoViolations });/expect.extend({ toHaveNoViolations } as any);/' "$file"
done

echo "Finished fixing remaining test issues"
