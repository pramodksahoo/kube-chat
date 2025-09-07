#!/bin/bash

# Fix common test file issues
find src -name "*.test.tsx" -o -name "*.test.ts" | while read file; do
  echo "Fixing $file..."
  
  # Remove unused imports
  sed -i '' '/import.*vi.*from.*vitest/s/, vi//' "$file"
  sed -i '' '/import.*waitFor.*from.*@testing-library/s/, waitFor//' "$file"  
  sed -i '' '/import.*fireEvent.*from.*@testing-library/s/, fireEvent//' "$file"
  sed -i '' '/import.*within.*from.*@testing-library/s/, within//' "$file"
  
  # Fix jest-axe extend calls - make them properly typed
  sed -i '' 's/expect\.extend(toHaveNoViolations);/expect.extend({ toHaveNoViolations });/' "$file"
  
done

echo "Test fixes complete"
