/**
 * Knowledge Graph & Entity Relationship Engine
 * Builds a provenance-aware graph of the target, source-returned indicators,
 * candidate profiles, and observed technical facts. Edges are leads, not proof.
 */

export interface GraphNode {
  id: string;
  label: string;
  type: "target" | "email" | "phone" | "domain" | "ip" | "username" | "platform" | "crypto" | "location" | "carrier" | "metadata";
  category: string;
  icon?: string;
  avatar?: string;
  details?: string;
  risk?: "low" | "medium" | "high";
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label: string;
  confidence: "high" | "medium" | "low";
}

export interface KnowledgeGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: {
    nodeCount: number;
    edgeCount: number;
    clustersCount: number;
    density: number;
  };
}

export function buildKnowledgeGraph(
  query: string,
  searchType: string,
  entities: {
    names?: string[];
    profile_pictures?: string[];
    banners?: string[];
    usernames?: string[];
    emails?: string[];
    phones?: string[];
    first_seen?: string;
    last_seen?: string;
  },
  evidence: {
    provider: string;
    category?: string | null;
    profile_url?: string | null;
    domain?: string | null;
    status: string;
    identity_name?: string | null;
    identifier_display?: string | null;
    confidence?: string | null;
    detail?: string | null;
    extra_fields?: Record<string, string>;
  }[]
): KnowledgeGraph {
  const nodesMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  let edgeIdSeq = 1;

  function addNode(node: GraphNode) {
    if (!nodesMap.has(node.id)) {
      nodesMap.set(node.id, node);
    }
  }

  function addEdge(source: string, target: string, relationship: string, label: string, confidence: "high" | "medium" | "low" = "high") {
    if (source === target) return;
    const edgeId = `edge_${edgeIdSeq++}`;
    edges.push({
      id: edgeId,
      source,
      target,
      relationship,
      label,
      confidence,
    });
  }

  // 1. Root Target Node
  const targetId = `target:${query}`;
  const targetType = (searchType || "target") as GraphNode["type"];
  addNode({
    id: targetId,
    label: query,
    type: "target",
    category: `Target (${searchType.toUpperCase()})`,
    avatar: entities.profile_pictures?.[0],
    details: `Root investigation target of type ${searchType}.`,
  });

  // 2. Discovered Identity Names
  if (entities.names && entities.names.length > 0) {
    entities.names.forEach((name, idx) => {
      if (name.toLowerCase() === query.toLowerCase()) return;
      const nameId = `name:${name}`;
      addNode({
        id: nameId,
        label: name,
        type: "username",
        category: "Name Indicator",
        avatar: entities.profile_pictures?.[idx] || entities.profile_pictures?.[0],
        details: `Name string returned by a source. Its association with the target is not independently verified.`,
        });
      addEdge(targetId, nameId, "identifies_as", "Identifies As");
    });
  }

  // 3. Discovered Usernames
  if (entities.usernames && entities.usernames.length > 0) {
    entities.usernames.forEach((u) => {
      if (u.toLowerCase() === query.toLowerCase()) return;
      const uId = `user:${u}`;
      addNode({
        id: uId,
        label: `@${u}`,
        type: "username",
        category: "Digital Handle",
        details: `Discovered public username handle @${u}.`,
        });
      addEdge(targetId, uId, "username_indicator", "Username Indicator", "medium");
    });
  }

  // 4. Discovered Emails
  if (entities.emails && entities.emails.length > 0) {
    entities.emails.forEach((email) => {
      if (email.toLowerCase() === query.toLowerCase()) return;
      const eId = `email:${email}`;
      addNode({
        id: eId,
        label: email,
        type: "email",
        category: "Email Indicator",
        details: "Email string returned by a source; mailbox control and relationship to the target are not established.",
      });
      addEdge(targetId, eId, "email_indicator", "Email Indicator", "medium");
    });
  }

  // 5. Discovered Phone Numbers
  if (entities.phones && entities.phones.length > 0) {
    entities.phones.forEach((phone) => {
      if (phone.toLowerCase() === query.toLowerCase()) return;
      const pId = `phone:${phone}`;
      addNode({
        id: pId,
        label: phone,
        type: "phone",
        category: "Phone Indicator",
        details: "Phone-like value returned by a source; subscriber identity and relationship to the target are not established.",
      });
      addEdge(targetId, pId, "phone_indicator", "Phone Indicator", "medium");
    });
  }

  // 6. Candidate profiles and technical observations remain distinct graph facts.
  const candidates = evidence.filter(e => e.status === "candidate");
  const observations = evidence.filter(e => e.status === "observed");
  candidates.forEach((cand, idx) => {
    const platId = `platform:${cand.provider.toLowerCase().replace(/[^a-z0-9]/g, "_")}_${idx}`;
    const avatar = cand.extra_fields?.Avatar;

    addNode({
      id: platId,
      label: cand.provider,
      type: "platform",
      category: cand.category || "Social & Services",
      icon: cand.domain || `${cand.provider.toLowerCase()}.com`,
      avatar,
      details: cand.detail || cand.identifier_display || `Candidate profile lead from ${cand.provider}; ownership is not established.`,
    });

    addEdge(targetId, platId, "candidate_profile", "Candidate Profile", cand.confidence === "high" ? "high" : "medium");

    // Cross-link platform to discovered name if identity_name is present
    if (cand.identity_name && nodesMap.has(`name:${cand.identity_name}`)) {
      addEdge(platId, `name:${cand.identity_name}`, "candidate_name_association", "Candidate Name Association", "medium");
    }
  });

  observations.forEach((item, idx) => {
    const observationId = `observation:${item.provider.toLowerCase().replace(/[^a-z0-9]/g, "_")}_${idx}`;
    addNode({
      id: observationId,
      label: item.provider,
      type: "platform",
      category: item.category || "Technical observation",
      icon: item.domain || undefined,
      details: item.detail || item.identifier_display || "Source returned a technical observation.",
      risk: "low",
    });
    addEdge(targetId, observationId, "source_observation", "Observed", item.confidence === "high" ? "high" : "medium");
  });

  const nodes = Array.from(nodesMap.values());
  const density = nodes.length > 1 ? Number((edges.length / (nodes.length * (nodes.length - 1))).toFixed(4)) : 0;

  return {
    nodes,
    edges,
    summary: {
      nodeCount: nodes.length,
      edgeCount: edges.length,
      clustersCount: Math.min(nodes.length, 4),
      density,
    },
  };
}
