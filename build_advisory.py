#!/usr/bin/env python3
"""
Inspira CyberPulse advisory builder.

Usage:
  python3 build_advisory.py spec.json [out_dir]

Builds the advisory .docx from the matching branded template
(templates/threat.docx or templates/vulnerability.docx) and, when the spec
has "iocs", the companion IOC .xlsx.

Spec format (JSON):
{
  "type": "threat" | "vulnerability",
  "id": "TA14112026.01",
  "title": "Short Headline Title",
  "blocks": [
    {"h": "Executive Summary"},                 # numbered section heading (auto 1., 2., ...)
    {"p": "Paragraph with **bold** parts."},
    {"kv": [["Threat", "..."], ["Research", "..."]]},          # label/value table
    {"table": {"header": ["CVE", "CVSS"], "rows": [["...", "..."]], "widths": [1, 3]}},
    {"h3": "Sub-heading"},
    {"bullets": ["**Lead:** text", "plain text"]},
    {"numbered": ["**Lead:** text", "..."]},                   # restarts at 1
    {"code": {"label": "1. Splunk: what it finds", "lines": ["index=...", "| stats ..."]}},
    {"refs": [{"text": "Source: Article title", "url": "https://..."}]}
  ],
  "iocs": [["IPv4", "1[.]2[.]3[.]4", "Source: context"], ...]   # optional, already defanged
}
"""
import copy, json, os, re, sys
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml.ns import qn

HERE = os.path.dirname(os.path.abspath(__file__))
COVER_END = 40  # body index of the paragraph holding the cover section break

# Prototype element indexes inside each template's body
PROTO = {
    "threat": dict(h=58, p=42, spacer=43, kv=44, h3=46, bullet=47, numbered=72,
                   ref=82, table=None, code_label=None, code=None),
    "vulnerability": dict(h=41, p=42, spacer=44, kv=43, h3=51, bullet=53, numbered=75,
                          ref=83, table=49, code_label=64, code=65),
}
PH_ID, PH_TITLE, PH_TYPE = "TA00000000.00", "{{TITLE}}", "{{TYPE}}"


def runs_from_md(text):
    """Split '**bold** plain' into [(text, bold)]."""
    out = []
    for i, part in enumerate(re.split(r"\*\*", text)):
        if part:
            out.append((part, i % 2 == 1))
    return out


def set_runs(p_el, text, base_rpr=None):
    """Replace all runs/hyperlinks of paragraph p_el with md-formatted runs."""
    rprs = [r.find(qn("w:rPr")) for r in p_el.iter(qn("w:r"))]
    rprs = [x for x in rprs if x is not None]
    plain = base_rpr
    if plain is None:
        plain = next((x for x in rprs if x.find(qn("w:b")) is None), rprs[0] if rprs else None)
    for child in list(p_el):
        if child.tag != qn("w:pPr"):
            p_el.remove(child)
    for seg, bold in runs_from_md(text):
        r = p_el.makeelement(qn("w:r"), {})
        if plain is not None:
            rpr = copy.deepcopy(plain)
            for b in rpr.findall(qn("w:b")) + rpr.findall(qn("w:bCs")):
                rpr.remove(b)
            if bold:
                rpr.insert(0, rpr.makeelement(qn("w:b"), {}))
            r.append(rpr)
        elif bold:
            rpr = r.makeelement(qn("w:rPr"), {})
            rpr.append(rpr.makeelement(qn("w:b"), {}))
            r.append(rpr)
        t = r.makeelement(qn("w:t"), {})
        t.text = seg
        t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        r.append(t)
        p_el.append(r)
    return p_el


class Builder:
    def __init__(self, kind):
        self.kind = kind
        self.doc = docx.Document(os.path.join(HERE, "templates", f"{kind}.docx"))
        body = self.doc.element.body
        self.body = body
        kids = list(body.iterchildren())
        self.protos = {k: copy.deepcopy(kids[i]) for k, i in PROTO[kind].items() if i is not None}
        self.sectPr = kids[-1]
        for el in kids[COVER_END + 1:-1]:
            body.remove(el)
        self.sec_no = 0
        self.numbering = self.doc.part.numbering_part.element

    def add(self, el):
        self.sectPr.addprevious(el)
        return el

    def clone(self, key):
        return copy.deepcopy(self.protos[key])

    # --- blocks ---------------------------------------------------------
    def h(self, text):
        prev = self.sectPr.getprevious()
        if self.sec_no and prev is not None and "".join(prev.itertext()).strip():
            self.spacer()
        self.sec_no += 1
        label = f"{self.sec_no}. {text.upper() if self.kind == 'vulnerability' else text}"
        self.add(set_runs(self.clone("h"), f"**{label}**"))

    def p(self, text):
        self.add(set_runs(self.clone("p"), text))

    def spacer(self):
        sp = self.clone("spacer")
        for c in list(sp):
            if c.tag != qn("w:pPr"):
                sp.remove(c)
        self.add(sp)

    def h3(self, text):
        bold = self.kind == "vulnerability"
        self.add(set_runs(self.clone("h3"), f"**{text}**" if bold else text))

    def bullets(self, items):
        for it in items:
            self.add(set_runs(self.clone("bullet"), it))

    def new_num(self, proto_el):
        num_id = proto_el.find(qn("w:pPr")).find(qn("w:numPr")).find(qn("w:numId")).get(qn("w:val"))
        src = next(n for n in self.numbering.findall(qn("w:num")) if n.get(qn("w:numId")) == num_id)
        abs_id = src.find(qn("w:abstractNumId")).get(qn("w:val"))
        new_id = str(max(int(n.get(qn("w:numId"))) for n in self.numbering.findall(qn("w:num"))) + 1)
        num = self.numbering.makeelement(qn("w:num"), {qn("w:numId"): new_id})
        a = num.makeelement(qn("w:abstractNumId"), {qn("w:val"): abs_id})
        num.append(a)
        ov = num.makeelement(qn("w:lvlOverride"), {qn("w:ilvl"): "0"})
        so = ov.makeelement(qn("w:startOverride"), {qn("w:val"): "1"})
        ov.append(so)
        num.append(ov)
        self.numbering.append(num)
        return new_id

    def numbered(self, items):
        proto = self.clone("numbered")
        nid = self.new_num(proto)
        for it in items:
            el = set_runs(self.clone("numbered"), it)
            el.find(qn("w:pPr")).find(qn("w:numPr")).find(qn("w:numId")).set(qn("w:val"), nid)
            self.add(el)

    def refs(self, items):
        for it in items:
            if isinstance(it, str):
                it = {"text": it, "url": it}
            el = self.clone("ref")
            link = el.find(qn("w:hyperlink"))
            rid = self.doc.part.relate_to(it["url"], RT.HYPERLINK, is_external=True)
            rpr = copy.deepcopy(next(link.iter(qn("w:r"))).find(qn("w:rPr")))
            for c in list(el):
                if c.tag != qn("w:pPr"):
                    el.remove(c)
            hl = el.makeelement(qn("w:hyperlink"), {qn("r:id"): rid, qn("w:history"): "1"})
            r = hl.makeelement(qn("w:r"), {})
            if rpr is not None:
                r.append(rpr)
            t = r.makeelement(qn("w:t"), {})
            t.text = it.get("text") or it["url"]
            r.append(t)
            hl.append(r)
            el.append(hl)
            self.add(el)

    def code(self, spec):
        if self.kind != "vulnerability":
            # threat template has no code prototype: borrow plain para in monospace
            if spec.get("label"):
                self.p(f"**{spec['label']}**")
            for line in spec.get("lines", []):
                el = set_runs(self.clone("p"), line)
                for r in el.iter(qn("w:r")):
                    rpr = r.find(qn("w:rPr"))
                    if rpr is None:
                        rpr = r.makeelement(qn("w:rPr"), {})
                        r.insert(0, rpr)
                    f = rpr.makeelement(qn("w:rFonts"), {qn("w:ascii"): "Consolas", qn("w:hAnsi"): "Consolas", qn("w:cs"): "Consolas"})
                    rpr.insert(0, f)
                    sz = rpr.makeelement(qn("w:sz"), {qn("w:val"): "17"})
                    rpr.append(sz)
                self.add(el)
            self.spacer()
            return
        if spec.get("label"):
            self.add(set_runs(self.clone("code_label"), f"**{spec['label']}**"))
        for line in spec.get("lines", []):
            self.add(set_runs(self.clone("code"), line))
        self.spacer()

    def _fill_cell(self, tc, text):
        ps = tc.findall(qn("w:p"))
        for extra in ps[1:]:
            tc.remove(extra)
        set_runs(ps[0], text)

    def kv(self, rows):
        tbl = self.clone("kv")
        trs = tbl.findall(qn("w:tr"))
        proto_row = trs[1] if len(trs) > 1 else trs[0]
        is_vuln = self.kind == "vulnerability"
        header = trs[0] if is_vuln else None
        for tr in trs:
            tbl.remove(tr)
        if header is not None:
            tbl.append(header)  # "Item | Status" header row
        for k, v in rows:
            tr = copy.deepcopy(proto_row)
            for h in tr.iter(qn("w:trHeight")):
                h.getparent().remove(h)
            tcs = tr.findall(qn("w:tc"))
            self._fill_cell(tcs[0], k if is_vuln else f"**{k}**")
            self._fill_cell(tcs[1], v)
            tbl.append(tr)
        self.add(tbl)
        self.spacer()

    def table(self, spec):
        return self._grid(spec, self.protos["table"] if self.kind == "vulnerability" else self.protos["kv"])

    def _grid(self, spec, proto):
        hdr, rows = spec["header"], spec["rows"]
        n = len(hdr)
        tbl = copy.deepcopy(proto)
        grid = tbl.find(qn("w:tblGrid"))
        total = sum(int(g.get(qn("w:w"))) for g in grid.findall(qn("w:gridCol")))
        weights = spec.get("widths") or [1] * n
        ws = [int(total * w / sum(weights)) for w in weights]
        for g in list(grid):
            grid.remove(g)
        for w in ws:
            grid.append(grid.makeelement(qn("w:gridCol"), {qn("w:w"): str(w)}))
        trs = tbl.findall(qn("w:tr"))
        hrow, brow = trs[0], trs[1] if len(trs) > 1 else trs[0]
        for tr in trs:
            tbl.remove(tr)

        def make_row(proto_tr, values, bold_first=False):
            tr = copy.deepcopy(proto_tr)
            for h in tr.iter(qn("w:trHeight")):
                h.getparent().remove(h)
            tcs = tr.findall(qn("w:tc"))
            tmpl = tcs[-1] if not bold_first else tcs[-1]
            for tc in tcs:
                tr.remove(tc)
            for i, (val, w) in enumerate(zip(values, ws)):
                src = tcs[0] if (i == 0 and len(tcs) > 1) else tmpl
                tc = copy.deepcopy(src)
                tcpr = tc.find(qn("w:tcPr"))
                if tcpr is not None:
                    tw = tcpr.find(qn("w:tcW"))
                    if tw is not None:
                        tw.set(qn("w:w"), str(w)); tw.set(qn("w:type"), "dxa")
                    gs = tcpr.find(qn("w:gridSpan"))
                    if gs is not None:
                        tcpr.remove(gs)
                self._fill_cell(tc, val)
                tr.append(tc)
            return tr

        is_vuln = self.kind == "vulnerability"
        tbl.append(make_row(hrow, hdr if is_vuln else [f"**{h}**" for h in hdr]))
        for r in rows:
            tbl.append(make_row(brow, r))
        self.add(tbl)
        self.spacer()

    # --- cover / header / footer ---------------------------------------
    def set_meta(self, adv_id, title, typ):
        def swap(root):
            for t in root.iter(qn("w:t")):
                if t.text:
                    t.text = t.text.replace(PH_ID, adv_id).replace(PH_TITLE, title).replace(PH_TYPE, typ)
        swap(self.body)
        for s in self.doc.sections:
            for part in (s.header, s.footer, s.first_page_header, s.first_page_footer):
                try:
                    swap(part._element)
                except Exception:
                    pass
        self.doc.core_properties.title = f"{adv_id} {title}"

    def save(self, path):
        self.doc.save(path)


def safe(s):
    return re.sub(r"[^A-Za-z0-9.\-]+", "_", s).strip("_")


def build_iocs(adv_id, title, iocs, path):
    import openpyxl
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "IOCs"
    ws.append(["IOC Type", "IOC (Defanged)", "Context"])
    for row in iocs:
        ws.append(list(row)[:3])
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c in ws[1]:
        c.font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F4E79")
        c.alignment = Alignment(vertical="center", wrap_text=True)
        c.border = border
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="Calibri", size=11)
            c.alignment = Alignment(vertical="top", wrap_text=True)
            c.border = border
    for col, w in zip("ABC", (18, 70, 95)):
        ws.column_dimensions[col].width = w
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:C{ws.max_row}"
    wb.save(path)


def main():
    spec = json.load(open(sys.argv[1]))
    out = sys.argv[2] if len(sys.argv) > 2 else "."
    os.makedirs(out, exist_ok=True)
    kind = spec["type"].lower()
    b = Builder(kind)
    b.set_meta(spec["id"], spec["title"], "Threat" if kind == "threat" else "Vulnerability")
    for blk in spec["blocks"]:
        (k, v), = blk.items()
        getattr(b, k)(v)
    docx_path = os.path.join(out, f"Inspira_CyberPulse_{spec['id']}_{safe(spec['title'])}.docx")
    b.save(docx_path)
    print(docx_path)
    if spec.get("iocs"):
        short = spec.get("ioc_name") or safe(spec["title"]).split("_")[0]
        x = os.path.join(out, f"Inspira_CyberPulse_{spec['id']}_{short}_IOCs.xlsx")
        build_iocs(spec["id"], spec["title"], spec["iocs"], x)
        print(x)


if __name__ == "__main__":
    main()
