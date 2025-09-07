/**
 * ResourceRelationshipGraph - Force-directed graph visualization for resource dependencies
 * Displays Kubernetes resources and their relationships using interactive nodes and edges
 */

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface GraphNode {
  id: string;
  resource: ResourceStatus;
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number; // Fixed x position
  fy?: number; // Fixed y position
  radius: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: 'owns' | 'controls' | 'selects' | 'mounts' | 'references' | 'depends-on';
}

export interface ResourceRelationshipGraphProps {
  resources: ResourceStatus[];
  selectedResource?: ResourceStatus | null;
  onResourceSelect?: (resource: ResourceStatus) => void;
  onResourceHover?: (resource: ResourceStatus | null) => void;
  className?: string;
  width?: number;
  height?: number;
  interactive?: boolean;
  showLabels?: boolean;
  filterByNamespace?: string;
}

interface SimulationConfig {
  charge: number;
  linkDistance: number;
  centerForce: number;
  velocityDecay: number;
}

export const ResourceRelationshipGraph: React.FC<ResourceRelationshipGraphProps> = memo(({
  resources,
  selectedResource,
  onResourceSelect,
  onResourceHover,
  className = '',
  width = 800,
  height = 600,
  interactive = true,
  showLabels = true,
  filterByNamespace,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number | undefined>(undefined);
  
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [draggedNode, setDraggedNode] = useState<GraphNode | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Configuration for force simulation
  const config: SimulationConfig = {
    charge: -300,
    linkDistance: 80,
    centerForce: 0.3,
    velocityDecay: 0.4,
  };

  // Filter resources by namespace if specified
  const filteredResources = React.useMemo(() => {
    if (!filterByNamespace) return resources;
    return resources.filter(resource => resource.namespace === filterByNamespace);
  }, [resources, filterByNamespace]);

  // Build graph data structure from resources
  const buildGraphData = useCallback(() => {
    const nodeMap = new Map<string, GraphNode>();
    const edgeSet = new Set<string>();
    const newEdges: GraphEdge[] = [];

    // Create nodes for all resources
    filteredResources.forEach(resource => {
      const nodeId = `${resource.kind}-${resource.name}-${resource.namespace || 'cluster'}`;
      const radius = getNodeRadius(resource.kind);
      
      nodeMap.set(nodeId, {
        id: nodeId,
        resource,
        x: Math.random() * width,
        y: Math.random() * height,
        vx: 0,
        vy: 0,
        radius,
      });
    });

    // Create edges from relationships
    filteredResources.forEach(resource => {
      const sourceId = `${resource.kind}-${resource.name}-${resource.namespace || 'cluster'}`;
      
      resource.relationships.forEach(rel => {
        const targetId = `${rel.kind}-${rel.name}-${rel.namespace || 'cluster'}`;
        const edgeKey = `${sourceId}-${targetId}-${rel.relationship}`;
        
        // Only create edge if both nodes exist and edge doesn't already exist
        if (nodeMap.has(sourceId) && nodeMap.has(targetId) && !edgeSet.has(edgeKey)) {
          edgeSet.add(edgeKey);
          newEdges.push({
            source: sourceId,
            target: targetId,
            relationship: rel.relationship,
          });
        }
      });
    });

    setNodes(Array.from(nodeMap.values()));
    setEdges(newEdges);
  }, [filteredResources, width, height]);

  // Get node radius based on resource kind
  const getNodeRadius = (kind: string): number => {
    const sizeMap: Record<string, number> = {
      'Namespace': 25,
      'Deployment': 20,
      'Service': 18,
      'Pod': 15,
      'ConfigMap': 12,
      'Secret': 12,
      'Ingress': 18,
      'PersistentVolume': 16,
      'PersistentVolumeClaim': 14,
    };
    return sizeMap[kind] || 15;
  };

  // Get node color based on resource status
  const getNodeColor = (resource: ResourceStatus, isSelected: boolean, isHovered: boolean): string => {
    if (isSelected) return '#3B82F6'; // blue-500
    if (isHovered) return '#60A5FA'; // blue-400
    
    const colorMap: Record<string, string> = {
      'Ready': '#10B981', // green-500
      'Warning': '#F59E0B', // amber-500
      'Error': '#EF4444', // red-500
      'Pending': '#8B5CF6', // violet-500
      'Unknown': '#6B7280', // gray-500
    };
    return colorMap[resource.status] || '#6B7280';
  };

  // Get edge color based on relationship type
  const getEdgeColor = (relationship: string): string => {
    const colorMap: Record<string, string> = {
      'owns': '#10B981', // green-500
      'controls': '#3B82F6', // blue-500
      'selects': '#8B5CF6', // violet-500
      'mounts': '#F59E0B', // amber-500
      'references': '#6B7280', // gray-500
    };
    return colorMap[relationship] || '#6B7280';
  };

  // Simple force simulation implementation
  const runSimulation = useCallback(() => {
    if (nodes.length === 0) return;

    const centerX = width / 2;
    const centerY = height / 2;

    // Apply forces to nodes
    nodes.forEach(node => {
      if (node.fx !== undefined && node.fy !== undefined) {
        node.x = node.fx;
        node.y = node.fy;
        node.vx = 0;
        node.vy = 0;
        return;
      }

      // Repulsion force between nodes
      nodes.forEach(other => {
        if (node === other) return;
        
        const dx = node.x - other.x;
        const dy = node.y - other.y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = config.charge / (distance * distance);
        
        node.vx += (dx / distance) * force;
        node.vy += (dy / distance) * force;
      });

      // Attraction force from edges
      edges.forEach(edge => {
        const source = nodes.find(n => n.id === edge.source);
        const target = nodes.find(n => n.id === edge.target);
        
        if (!source || !target) return;
        
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (distance - config.linkDistance) * 0.1;
        
        if (node === source) {
          node.vx += (dx / distance) * force;
          node.vy += (dy / distance) * force;
        } else if (node === target) {
          node.vx -= (dx / distance) * force;
          node.vy -= (dy / distance) * force;
        }
      });

      // Center force
      const centerDx = centerX - node.x;
      const centerDy = centerY - node.y;
      node.vx += centerDx * config.centerForce * 0.01;
      node.vy += centerDy * config.centerForce * 0.01;

      // Apply velocity decay
      node.vx *= config.velocityDecay;
      node.vy *= config.velocityDecay;

      // Update position
      node.x += node.vx;
      node.y += node.vy;

      // Boundary constraints
      const padding = node.radius;
      node.x = Math.max(padding, Math.min(width - padding, node.x));
      node.y = Math.max(padding, Math.min(height - padding, node.y));
    });

    setNodes([...nodes]);
  }, [nodes, edges, width, height, config]);

  // Animation loop
  const animate = useCallback(() => {
    runSimulation();
    animationRef.current = requestAnimationFrame(animate);
  }, [runSimulation]);

  // Start/stop animation
  useEffect(() => {
    if (nodes.length > 0) {
      animationRef.current = requestAnimationFrame(animate);
    }
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [animate, nodes.length]);

  // Build graph data when resources change
  useEffect(() => {
    buildGraphData();
  }, [buildGraphData]);

  // Canvas rendering
  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, width, height);

    // Draw edges
    edges.forEach(edge => {
      const source = nodes.find(n => n.id === edge.source);
      const target = nodes.find(n => n.id === edge.target);
      
      if (!source || !target) return;

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = getEdgeColor(edge.relationship);
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw arrow head
      const angle = Math.atan2(target.y - source.y, target.x - source.x);
      const arrowLength = 10;
      const arrowAngle = Math.PI / 6;

      const endX = target.x - Math.cos(angle) * target.radius;
      const endY = target.y - Math.sin(angle) * target.radius;

      ctx.beginPath();
      ctx.moveTo(endX, endY);
      ctx.lineTo(
        endX - arrowLength * Math.cos(angle - arrowAngle),
        endY - arrowLength * Math.sin(angle - arrowAngle)
      );
      ctx.moveTo(endX, endY);
      ctx.lineTo(
        endX - arrowLength * Math.cos(angle + arrowAngle),
        endY - arrowLength * Math.sin(angle + arrowAngle)
      );
      ctx.stroke();
    });

    // Draw nodes
    nodes.forEach(node => {
      const isSelected = selectedResource?.name === node.resource.name &&
                        selectedResource?.kind === node.resource.kind &&
                        selectedResource?.namespace === node.resource.namespace;
      const isHovered = hoveredNode?.id === node.id;

      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
      ctx.fillStyle = getNodeColor(node.resource, isSelected, isHovered);
      ctx.fill();
      
      // Node border
      ctx.strokeStyle = isSelected ? '#1D4ED8' : '#374151'; // blue-700 : gray-700
      ctx.lineWidth = isSelected ? 3 : 1;
      ctx.stroke();

      // Node label
      if (showLabels) {
        ctx.fillStyle = '#1F2937'; // gray-800
        ctx.font = '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        
        const labelY = node.y + node.radius + 15;
        ctx.fillText(node.resource.name, node.x, labelY);
        
        // Kind label
        ctx.font = '10px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        ctx.fillStyle = '#6B7280'; // gray-500
        ctx.fillText(node.resource.kind, node.x, labelY + 12);
      }
    });
  }, [nodes, edges, selectedResource, hoveredNode, showLabels]);

  // Redraw when nodes or selection changes
  useEffect(() => {
    draw();
  }, [draw]);

  // Mouse event handlers
  const handleMouseMove = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Handle dragging
    if (isDragging && draggedNode) {
      draggedNode.fx = x;
      draggedNode.fy = y;
      return;
    }

    // Find hovered node
    const hoveredNodeFound = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    if (hoveredNodeFound !== hoveredNode) {
      setHoveredNode(hoveredNodeFound || null);
      onResourceHover?.(hoveredNodeFound?.resource || null);
    }

    // Update cursor
    if (canvas) {
      canvas.style.cursor = hoveredNodeFound ? 'pointer' : 'default';
    }
  }, [interactive, nodes, hoveredNode, isDragging, draggedNode, onResourceHover]);

  const handleMouseDown = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const clickedNode = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    if (clickedNode) {
      setDraggedNode(clickedNode);
      setIsDragging(true);
      clickedNode.fx = x;
      clickedNode.fy = y;
    }
  }, [interactive, nodes]);

  const handleMouseUp = useCallback(() => {
    if (isDragging && draggedNode) {
      // Release fixed position to allow simulation to resume
      delete draggedNode.fx;
      delete draggedNode.fy;
    }
    
    setIsDragging(false);
    setDraggedNode(null);
  }, [isDragging, draggedNode]);

  const handleClick = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!interactive || isDragging) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const clickedNode = nodes.find(node => {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= node.radius;
    });

    if (clickedNode) {
      onResourceSelect?.(clickedNode.resource);
    }
  }, [interactive, nodes, isDragging, onResourceSelect]);

  return (
    <div className={`resource-relationship-graph ${className}`} data-testid="resource-relationship-graph">
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className="border border-gray-200 rounded-lg bg-white"
        onMouseMove={handleMouseMove}
        onMouseDown={handleMouseDown}
        onMouseUp={handleMouseUp}
        onClick={handleClick}
        data-testid="relationship-canvas"
      />
      
      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-4 text-sm">
        <div className="flex items-center gap-2">
          <span className="font-medium text-gray-700">Status:</span>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="text-xs text-gray-600">Ready</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-amber-500"></div>
            <span className="text-xs text-gray-600">Warning</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <span className="text-xs text-gray-600">Error</span>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <span className="font-medium text-gray-700">Relations:</span>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-green-500"></div>
            <span className="text-xs text-gray-600">owns</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-blue-500"></div>
            <span className="text-xs text-gray-600">controls</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-0.5 bg-violet-500"></div>
            <span className="text-xs text-gray-600">selects</span>
          </div>
        </div>
      </div>

      {/* Resource count */}
      <div className="mt-2 text-xs text-gray-500">
        Showing {nodes.length} resources with {edges.length} relationships
        {filterByNamespace && ` in namespace: ${filterByNamespace}`}
      </div>
    </div>
  );
});

ResourceRelationshipGraph.displayName = 'ResourceRelationshipGraph';

export default ResourceRelationshipGraph;