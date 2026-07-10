"""
HARMATTAN — GraphML / GEXF export for Gephi & yEd.
"""
from __future__ import annotations

from xml.sax.saxutils import escape


def build_graphml(nodes: list[dict], edges: list[dict]) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="role" for="node" attr.name="role" attr.type="string"/>',
        '  <key id="ip" for="node" attr.name="ip" attr.type="string"/>',
        '  <key id="mac" for="node" attr.name="mac" attr.type="string"/>',
        '  <key id="vendor" for="node" attr.name="vendor" attr.type="string"/>',
        '  <graph id="G" edgedefault="undirected">',
    ]
    for n in nodes:
        nid = escape(str(n.get("id") or ""))
        if not nid:
            continue
        label = escape(str(n.get("label") or n.get("id") or ""))
        role = escape(str(n.get("role") or n.get("group") or ""))
        ip = escape(str(n.get("ip") or (n.get("id") if str(n.get("id", "")).count(".") == 3 else "")))
        mac = escape(str(n.get("mac") or ""))
        vendor = escape(str(n.get("vendor") or ""))
        lines.append(f'    <node id="{nid}">')
        lines.append(f'      <data key="label">{label}</data>')
        lines.append(f'      <data key="role">{role}</data>')
        lines.append(f'      <data key="ip">{ip}</data>')
        lines.append(f'      <data key="mac">{mac}</data>')
        lines.append(f'      <data key="vendor">{vendor}</data>')
        lines.append("    </node>")
    for i, e in enumerate(edges):
        frm = escape(str(e.get("from") or e.get("source") or ""))
        to = escape(str(e.get("to") or e.get("target") or ""))
        if not frm or not to:
            continue
        eid = escape(str(e.get("id") or f"e{i}"))
        lines.append(f'    <edge id="{eid}" source="{frm}" target="{to}"/>')
    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines)


def build_gexf(nodes: list[dict], edges: list[dict], title: str = "HARMATTAN") -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">',
        "  <meta>",
        f"    <creator>HARMATTAN</creator>",
        f"    <description>{escape(title)}</description>",
        "  </meta>",
        '  <graph mode="static" defaultedgetype="undirected">',
        "    <attributes class=\"node\">",
        '      <attribute id="0" title="role" type="string"/>',
        '      <attribute id="1" title="vendor" type="string"/>',
        "    </attributes>",
        "    <nodes>",
    ]
    for n in nodes:
        nid = escape(str(n.get("id") or ""))
        if not nid:
            continue
        label = escape(str(n.get("label") or nid))
        role = escape(str(n.get("role") or ""))
        vendor = escape(str(n.get("vendor") or ""))
        lines.append(f'      <node id="{nid}" label="{label}">')
        lines.append("        <attvalues>")
        lines.append(f'          <attvalue for="0" value="{role}"/>')
        lines.append(f'          <attvalue for="1" value="{vendor}"/>')
        lines.append("        </attvalues>")
        lines.append("      </node>")
    lines.append("    </nodes>")
    lines.append("    <edges>")
    for i, e in enumerate(edges):
        frm = escape(str(e.get("from") or e.get("source") or ""))
        to = escape(str(e.get("to") or e.get("target") or ""))
        if not frm or not to:
            continue
        lines.append(f'      <edge id="{i}" source="{frm}" target="{to}"/>')
    lines.append("    </edges>")
    lines.append("  </graph>")
    lines.append("</gexf>")
    return "\n".join(lines)
