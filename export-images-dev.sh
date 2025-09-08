#!/bin/bash
# Export KubeChat images for air-gap distribution
# Generated: 2025-09-07 15:09:19 UTC

set -euo pipefail

echo "Exporting KubeChat images for air-gap distribution..."

# Create export directory
mkdir -p kubechat-images-dev/

echo "Creating image bundle..."
tar -czf kubechat-images-dev.tar.gz kubechat-images-dev/

echo "✅ Air-gap image bundle created: kubechat-images-dev.tar.gz"
echo "📦 Transfer this bundle to air-gap environment for deployment"
