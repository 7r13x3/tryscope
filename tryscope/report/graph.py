"""
TryScope - Cluster graph renderer
Draws an infrastructure cluster as a PNG using NetworkX + matplotlib.
"""
from pathlib import Path

from .. import logger


def render(cluster: dict, out_path: str) -> str:
    """Render the cluster as a static PNG graph."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import networkx as nx
    except ImportError:
        logger.warn("matplotlib or networkx not installed")
        return ""

    ip = cluster.get("nodes", {})
    edges = cluster.get("edges", [])

    if not edges:
        logger.warn("No cluster edges to render")
        return ""

    G = nx.Graph()
    for src, dst, rel in edges:
        G.add_edge(str(src), str(dst), label=rel)

    if len(G.nodes) == 0:
        return ""

    try:
        fig, ax = plt.subplots(figsize=(12, 8), dpi=100)
        fig.patch.set_facecolor("#0f1117")
        ax.set_facecolor("#0f1117")

        pos = nx.spring_layout(G, k=0.8, iterations=50, seed=42)

        # color nodes by type
        colors = []
        for n in G.nodes:
            n_str = str(n)
            if ":" in n_str and "AS" not in n_str:
                colors.append("#8892a0")   # pivot nodes
            elif n_str.startswith("AS"):
                colors.append("#4cc9f0")   # ASN nodes
            elif "." in n_str and n_str.replace(".", "").isdigit() is False:
                colors.append("#ffd43b")   # domains
            else:
                colors.append("#ff6b6b")   # IPs
        colors[0] = "#4cc9f0"

        nx.draw_networkx_edges(G, pos, alpha=0.3,
                              edge_color="#4cc9f0", ax=ax)
        nx.draw_networkx_nodes(G, pos, node_color=colors,
                              node_size=600, alpha=0.9, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=7,
                                font_color="white", ax=ax)

        ax.set_title(f"TryScope Cluster - {ip}",
                     color="#4cc9f0", fontsize=14)
        ax.axis("off")
        plt.tight_layout()

        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(str(out), facecolor="#0f1117", bbox_inches="tight")
        plt.close()

        logger.ok(f"Cluster graph saved: {out}")
        return str(out)
    except Exception as e:
        logger.warn(f"Graph render failed: {e}")
        return ""
