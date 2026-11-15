import type { AetherGraph, AffiliationEdge } from '../types/graph';

/**
 * Décode le transport compact du backend (`edges_compact`) en tableau d'arêtes classique.
 *
 * Le backend envoie les arêtes de gros projets (PrestaShop : 250k) sous forme de tableaux d'entiers
 * (indices de nœuds + tables de relations). Ici, `source` / `target` pointent vers LA MÊME chaîne
 * que `node.id` : aucune des ~500k chaînes d'identifiants n'est dupliquée dans le tas JS.
 */
export function decodeCompactGraph(g: any): AetherGraph {
  const c = g?.edges_compact;
  if (!c || !Array.isArray(c.src)) return g;

  const nodes: { id: string }[] = Array.isArray(g.nodes) ? g.nodes : [];
  const nCount = nodes.length;
  const extraIds: string[] = c.ids || [];
  const rels: string[] = c.rels || [];
  const types: string[] = c.types || [];
  const extra: Record<string, Partial<AffiliationEdge>> = c.extra || {};
  const { src, dst, rel, typ } = c as { src: number[]; dst: number[]; rel: number[]; typ: number[] };

  const idAt = (i: number): string => (i < nCount ? nodes[i].id : extraIds[i - nCount]);

  const total = src.length;
  const edges: AffiliationEdge[] = new Array(total);
  for (let i = 0; i < total; i++) {
    const e: AffiliationEdge = {
      source: idAt(src[i]),
      target: idAt(dst[i]),
      relation: rels[rel[i]],
      edge_type: types[typ[i]],
    };
    const x = extra[i];
    if (x) Object.assign(e, x);
    edges[i] = e;
  }

  const out: any = { ...g, edges };
  delete out.edges_compact;
  return out as AetherGraph;
}
