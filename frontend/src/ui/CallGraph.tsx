import { useMemo } from 'react';
import { ReactFlow, Background, Controls, Node, Edge, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// Dark Mode Theme Overrides for React Flow
const defaultEdgeOptions = {
  type: 'smoothstep',
  animated: true,
  style: { stroke: '#38bdf8', strokeWidth: 2 },
  markerEnd: { type: MarkerType.ArrowClosed, color: '#38bdf8' },
};

export function CallGraph({ functions }: { functions: any[] }) {
  
  // Transform our raw Python list into React Flow Nodes and Edges
  const { nodes, edges } = useMemo(() => {
    const newNodes: Node[] = [];
    const newEdges: Edge[] = [];
    const seenNodes = new Set<string>();

    let yOffsetCallers = 50;
    let yOffsetTargets = 50;

    functions.forEach((func, idx) => {
      // 1. Add the Suspicious Target Function (Node)
      if (!seenNodes.has(func.name)) {
        seenNodes.add(func.name);
        newNodes.push({
          id: func.name,
          position: { x: 450, y: yOffsetTargets },
          data: { label: `🚩 ${func.name} \nScore: ${func.suspicion_score}` },
          style: { background: '#1e1b4b', color: '#c7d2fe', border: '1px solid #4f46e5', borderRadius: '8px', padding: '10px', width: 220, fontSize: '12px' },
        });
        yOffsetTargets += 100;
      }

      // 2. Add the Callers (Nodes) and connect them (Edges)
      func.called_by.forEach((callerName: string) => {
        if (!seenNodes.has(callerName)) {
          seenNodes.add(callerName);
          newNodes.push({
            id: callerName,
            position: { x: 50, y: yOffsetCallers },
            data: { label: `Call: ${callerName}` },
            style: { background: '#0f172a', color: '#94a3b8', border: '1px solid #334155', borderRadius: '8px', padding: '10px', fontSize: '11px' },
          });
          yOffsetCallers += 70;
        }

        // Connect Caller -> Target
        newEdges.push({
          id: `e-${callerName}-${func.name}`,
          source: callerName,
          target: func.name,
        });
      });
    });

    return { nodes: newNodes, edges: newEdges };
  }, [functions]);

  if (nodes.length === 0) return <div className="p-4 text-slate-500 text-sm">No call graph data available.</div>;

  return (
    <div style={{ height: '400px', width: '100%', background: '#020617', borderRadius: '16px', overflow: 'hidden', border: '1px solid #1e293b' }}>
      <ReactFlow nodes={nodes} edges={edges} defaultEdgeOptions={defaultEdgeOptions} fitView attributionPosition="bottom-right">
        <Background color="#334155" gap={20} />
        <Controls style={{ background: '#0f172a', fill: '#c7d2fe' }} />
      </ReactFlow>
    </div>
  );
}