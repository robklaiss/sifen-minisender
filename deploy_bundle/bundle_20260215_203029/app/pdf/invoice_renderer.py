from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import simpleSplit, ImageReader
from urllib.parse import parse_qs, urlparse
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas


_ND = "N/D"

GRAY_LIGHT = colors.HexColor("#F2F2F2")
GRAY_BORDER = colors.HexColor("#D9D9D9")
GRAY_TEXT = colors.HexColor("#666666")
DARK_TEXT = colors.HexColor("#222222")
RED_SOFT = colors.HexColor("#C75C5C")
GREEN_SOFT = colors.HexColor("#2E7D32")

DEFAULT_KUDE_QR_BASE_URL = "https://ekuatia.set.gov.py/consultas/kude?cdc="


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return str(value)


def _first(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = _clean(value)
        if cleaned:
            return cleaned
    return None


def _safe(value: Any, fallback: str = _ND) -> str:
    return _clean(value) or fallback


def _safe_amount(value: Any) -> str:
    return _clean(value) or "0"


def _fmt_num(value: Any, *, decimals: int = 0, fallback: str = "0") -> str:
    cleaned = _clean(value)
    if cleaned is None:
        return fallback

    if isinstance(value, (int, float)):
        num = float(value)
    else:
        raw = cleaned.replace(" ", "")
        if not raw:
            return fallback

        if "," in raw and "." in raw:
            if raw.rfind(",") > raw.rfind("."):
                raw = raw.replace(".", "")
                raw = raw.replace(",", ".")
            else:
                raw = raw.replace(",", "")
        elif "." in raw:
            parts = raw.split(".")
            if len(parts) > 2 or (len(parts) == 2 and len(parts[1]) == 3 and parts[0].isdigit()):
                raw = raw.replace(".", "")
            else:
                raw = raw
        elif "," in raw:
            raw = raw.replace(",", ".")

        try:
            num = float(raw)
        except ValueError:
            return cleaned

    if decimals <= 0:
        formatted = f"{int(round(num)):,}"
        return formatted.replace(",", ".")

    formatted = f"{num:,.{decimals}f}"
    formatted = formatted.replace(",", "X").replace(".", ",").replace("X", ".")
    return formatted


def _to_num(value: Any) -> float:
    cleaned = _clean(value)
    if cleaned is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    raw = cleaned.replace(" ", "")
    if not raw:
        return 0.0
    if "," in raw and "." in raw:
        if raw.rfind(",") > raw.rfind("."):
            raw = raw.replace(".", "")
            raw = raw.replace(",", ".")
        else:
            raw = raw.replace(",", "")
    elif "." in raw:
        parts = raw.split(".")
        if len(parts) > 2 or (len(parts) == 2 and len(parts[1]) == 3 and parts[0].isdigit()):
            raw = raw.replace(".", "")
    elif "," in raw:
        raw = raw.replace(",", ".")
    try:
        return float(raw)
    except ValueError:
        return 0.0


def _normalize_iva_rate(value: Any) -> int:
    if value is None:
        return 0
    raw = str(value).strip().lower()
    if not raw:
        return 0
    if "exent" in raw:
        return 0
    digits = re.sub(r"\\D", "", raw)
    if digits == "5":
        return 5
    if digits == "10":
        return 10
    return 0


def _format_date(value: Any) -> str:
    cleaned = _clean(value)
    if not cleaned:
        return _ND
    date_part = cleaned.split("T")[0].split(" ")[0]
    if re.match(r"^\\d{4}-\\d{2}-\\d{2}$", date_part):
        y, m, d = date_part.split("-")
        return f"{d}/{m}/{y}"
    return date_part


def _extract_xml_fields(xml: str) -> Dict[str, str]:
    if not xml:
        return {}

    def find(tag: str) -> Optional[str]:
        pattern = rf"<(?:\\w+:)?{tag}>(.*?)</(?:\\w+:)?{tag}>"
        match = re.search(pattern, xml, flags=re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    fields = {}
    for key in [
        "dCodResLot",
        "dMsgResLot",
        "dProtConsLote",
        "dId",
        "dFecProc",
        "dCodRes",
        "dMsgRes",
        "dFecEmi",
        "dTotOpe",
        "dTotGralOpe",
        "dIVA10",
        "dIVA5",
        "dDCondOpe",
        "dNumRem",
    ]:
        value = find(key)
        if value:
            fields[key] = value
    return fields


def _extract_cdc(data: Dict[str, Any], parsed_fields: Dict[str, Any]) -> Optional[str]:
    cdc = _first(data.get("CDC"), data.get("cdc"))
    if cdc:
        return cdc

    cdc = _first(parsed_fields.get("CDC"), parsed_fields.get("cdc"))
    if cdc:
        return cdc

    cdc = _clean(parsed_fields.get("cdc"))
    if cdc:
        return cdc

    response_xml = _clean(data.get("response_xml"))
    if response_xml:
        match = re.search(r"<(?:\\w+:)?dCDC>(.*?)</(?:\\w+:)?dCDC>", response_xml, flags=re.DOTALL)
        if match:
            value = match.group(1).strip()
            return value or None

    return None


def _build_kude_qr_value(cdc: Optional[str]) -> str:
    if not cdc:
        return "KUDE:SIN_CDC"
    base = os.getenv("SIFEN_KUDE_QR_BASE_URL", DEFAULT_KUDE_QR_BASE_URL) or DEFAULT_KUDE_QR_BASE_URL
    return f"{base}{cdc}"


def _draw_qr(c: canvas.Canvas, x: float, y: float, size: float, value: str) -> None:
    if size <= 0:
        return
    value = value or "KUDE:SIN_CDC"
    qr = QrCodeWidget(value)
    bounds = qr.getBounds()
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    if width <= 0 or height <= 0:
        return
    drawing = Drawing(size, size, transform=[size / width, 0, 0, size / height, 0, 0])
    drawing.add(qr)
    renderPDF.draw(drawing, c, x, y)


def _get_field(
    data: Dict[str, Any],
    parsed: Dict[str, Any],
    xml_fields: Dict[str, Any],
    *keys: str,
) -> Optional[str]:
    for key in keys:
        if key in parsed and _clean(parsed.get(key)):
            return _clean(parsed.get(key))
        if key in data and _clean(data.get(key)):
            return _clean(data.get(key))
        if key in xml_fields and _clean(xml_fields.get(key)):
            return _clean(xml_fields.get(key))
    return None


def _wrap_text(value: str, font_name: str, font_size: int, width: float) -> Iterable[str]:
    return simpleSplit(value, font_name, font_size, width)


def _text_width(value: str, font_name: str, font_size: int) -> float:
    return pdfmetrics.stringWidth(value, font_name, font_size)


def _truncate_text(value: str, font_name: str, font_size: int, max_width: float, ellipsis: str = "...") -> str:
    if max_width <= 0:
        return ""
    if _text_width(value, font_name, font_size) <= max_width:
        return value
    ellipsis = ellipsis or ""
    ellipsis_width = _text_width(ellipsis, font_name, font_size)
    available = max_width - ellipsis_width
    if available <= 0:
        return ellipsis if ellipsis else value[:1]
    trimmed = value
    while trimmed and _text_width(trimmed, font_name, font_size) > available:
        trimmed = trimmed[:-1]
    return trimmed.rstrip() + ellipsis


def _wrap_and_truncate(
    value: str,
    font_name: str,
    font_size: int,
    max_width: float,
    *,
    max_lines: Optional[int] = None,
    max_height: Optional[float] = None,
    leading: Optional[float] = None,
) -> List[str]:
    if not value:
        value = _ND
    lines = list(_wrap_text(value, font_name, font_size, max_width)) or [_ND]
    if max_lines is None and max_height is not None and leading:
        max_lines = max(1, int(max_height // leading))
    if max_lines is not None and len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = _truncate_text(lines[-1], font_name, font_size, max_width)
    else:
        lines = [_truncate_text(line, font_name, font_size, max_width, ellipsis="") for line in lines]
    return lines


def _draw_hr(c: canvas.Canvas, y: float, x_left: float, x_right: float) -> None:
    c.setStrokeColor(GRAY_BORDER)
    c.setLineWidth(0.6)
    c.line(x_left, y, x_right, y)


def _draw_box(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    height: float,
    *,
    stroke_color: colors.Color = GRAY_BORDER,
    fill_color: Optional[colors.Color] = None,
    stroke_width: float = 0.7,
) -> None:
    c.setLineWidth(stroke_width)
    c.setStrokeColor(stroke_color)
    if fill_color is not None:
        c.setFillColor(fill_color)
        c.rect(x, y_top - height, width, height, stroke=1, fill=1)
        c.setFillColor(colors.black)
    else:
        c.rect(x, y_top - height, width, height, stroke=1, fill=0)


def _draw_lines(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    lines: List[str],
    font_name: str,
    font_size: int,
    leading: float,
    color: colors.Color,
    *,
    width: Optional[float] = None,
    align: str = "left",
) -> float:
    if not lines:
        return y_top
    c.setFont(font_name, font_size)
    c.setFillColor(color)
    y = y_top - font_size
    for line in lines:
        if align == "center" and width is not None:
            c.drawCentredString(x + width / 2, y, line)
        elif align == "right" and width is not None:
            c.drawRightString(x + width, y, line)
        else:
            c.drawString(x, y, line)
        y -= leading
    c.setFillColor(colors.black)
    return y_top - len(lines) * leading


def _format_ruc_dv(ruc: Any, dv: Any) -> str:
    ruc_clean = _clean(ruc)
    dv_clean = _clean(dv)
    if ruc_clean and dv_clean:
        return f"{ruc_clean}-{dv_clean}"
    if ruc_clean:
        return ruc_clean
    if dv_clean:
        return dv_clean
    return _ND


def _qr_hash_tail(qr_url: Optional[str], max_len: int = 10) -> Optional[str]:
    if not qr_url:
        return None
    try:
        parsed = urlparse(qr_url.replace("&amp;", "&"))
        qs = parse_qs(parsed.query)
        h = (qs.get("cHashQR") or [""])[0].strip()
        if not h:
            return None
        return h[-max_len:] if len(h) > max_len else h
    except Exception:
        return None


def _draw_header_left(c: canvas.Canvas, x: float, y_top: float, width: float, issuer: Dict[str, Any]) -> float:
    name_font = 15
    name_leading = 18
    detail_font = 9
    detail_leading = 12
    gap = 2 * mm

    name = _safe(issuer.get("razon_social"))
    logo_path = _clean(issuer.get("logo_path"))
    logo_size = 18 * mm
    logo_gap = 3 * mm
    text_x = x
    text_width = width
    if logo_path and Path(logo_path).exists() and width > logo_size + logo_gap + 40 * mm:
        try:
            img = ImageReader(logo_path)
            iw, ih = img.getSize()
            scale = min(logo_size / iw, logo_size / ih)
            w = iw * scale
            h = ih * scale
            img_x = x + (logo_size - w) / 2
            img_y = y_top - logo_size + (logo_size - h) / 2
            c.drawImage(img, img_x, img_y, w, h, mask="auto")
            text_x = x + logo_size + logo_gap
            text_width = width - logo_size - logo_gap
        except Exception:
            pass

    name_lines = _wrap_and_truncate(name, "Helvetica-Bold", name_font, text_width, max_lines=2)

    tagline = _clean(issuer.get("tagline"))
    direccion = _clean(issuer.get("direccion")) or _ND
    num_casa = _clean(issuer.get("num_casa"))
    if num_casa:
        direccion_l = direccion.lower()
        if all(token not in direccion_l for token in ("nr", "nro", "n°", "nº")):
            direccion = f"{direccion} Nr. {num_casa}"
    telefono = _clean(issuer.get("telefono"))
    email = _clean(issuer.get("email"))
    tel_email = ""
    if telefono and email:
        tel_email = f"Tel.: {telefono} - {email}"
    elif telefono:
        tel_email = f"Tel.: {telefono}"
    elif email:
        tel_email = email

    ciudad = _clean(issuer.get("ciudad"))
    ciudad_line = f"{ciudad} - Paraguay" if ciudad else ""

    details = []
    if tagline:
        details.append(tagline)
    details.append(direccion)
    if tel_email:
        details.append(tel_email)
    if ciudad_line:
        details.append(ciudad_line)

    detail_lines: List[str] = []
    for entry in details:
        detail_lines.extend(_wrap_and_truncate(entry, "Helvetica", detail_font, text_width, max_lines=2))

    if len(detail_lines) > 5:
        detail_lines = detail_lines[:4]
        detail_lines[-1] = _truncate_text(detail_lines[-1], "Helvetica", detail_font, text_width)

    current_y = y_top
    current_y = _draw_lines(c, text_x, current_y, name_lines, "Helvetica-Bold", name_font, name_leading, colors.black)
    if detail_lines:
        current_y -= gap
        current_y = _draw_lines(c, text_x, current_y, detail_lines, "Helvetica", detail_font, detail_leading, GRAY_TEXT)

    return y_top - current_y


def _draw_header_box(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    title: str,
    items: List[Tuple[str, str]],
) -> float:
    padding_x = 3 * mm
    padding_y = 2 * mm
    title_font = 16
    title_leading = 18
    item_font = 9
    item_leading = 12

    inner_width = max(10, width - 2 * padding_x)

    item_lines: List[str] = []
    for label, value in items:
        text = f"{label}: {value}"
        item_lines.extend(
            _wrap_and_truncate(text, "Helvetica", item_font, inner_width, max_lines=2)
        )

    bottom_extra = 3 * mm
    height = padding_y * 2 + title_leading + len(item_lines) * item_leading + bottom_extra

    _draw_box(c, x, y_top, width, height, stroke_color=GRAY_BORDER)

    current_y = y_top - padding_y
    current_y = _draw_lines(
        c,
        x,
        current_y,
        [title],
        "Helvetica-Bold",
        title_font,
        title_leading,
        colors.black,
        width=width,
        align="center",
    )
    gap_after_title = 2.5 * mm
    gap_after_line = 1.5 * mm
    line_y = current_y - gap_after_title
    c.setStrokeColor(GRAY_BORDER)
    c.setLineWidth(0.6)
    c.line(x + padding_x, line_y, x + width - padding_x, line_y)
    current_y = line_y - gap_after_line
    _draw_lines(
        c,
        x + padding_x,
        current_y,
        item_lines,
        "Helvetica",
        item_font,
        item_leading,
        DARK_TEXT,
    )

    return height


def _layout_kv_items(
    items: List[Tuple[str, str]],
    width: float,
    *,
    label_font_size: int = 8,
    value_font_size: int = 9,
    line_gap: float = 2,
    max_lines_per_item: int = 2,
    gap: float = 4,
) -> Tuple[List[Tuple[str, List[str]]], float, float, float, float]:
    labels = [label for label, _ in items]
    max_label_width = max((_text_width(label, "Helvetica", label_font_size) for label in labels), default=0)
    label_width = min(max_label_width + gap, width * 0.38)
    value_width = max(10, width - label_width - gap)
    leading = value_font_size + line_gap

    layout: List[Tuple[str, List[str]]] = []
    total_lines = 0
    for label, value in items:
        lines = _wrap_and_truncate(value, "Helvetica", value_font_size, value_width, max_lines=max_lines_per_item)
        layout.append((label, lines))
        total_lines += len(lines)

    return layout, total_lines * leading, label_width, value_width, leading


def _draw_kv_rows_with_lines(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    rows: List[Tuple[str, List[str]]],
    *,
    label_width: float,
    value_width: float,
    leading: float,
    padding_x: float,
    padding_y: float,
    line_color: colors.Color = GRAY_BORDER,
    label_color: colors.Color = GRAY_TEXT,
    value_color: colors.Color = colors.black,
    label_font_size: int = 8,
    value_font_size: int = 9,
    gap: float = 4,
) -> float:
    current_y = y_top
    label_x = x + padding_x
    value_right = x + padding_x + label_width + gap + value_width

    c.setStrokeColor(line_color)
    last_index = len(rows) - 1
    for idx, (label, lines) in enumerate(rows):
        if not lines:
            lines = [_ND]
        row_height = max(1, len(lines)) * leading + 2 * padding_y
        row_top = current_y
        row_bottom = row_top - row_height

        if idx < last_index:
            c.line(x, row_bottom, x + width, row_bottom)

        text_y = row_top - padding_y - value_font_size
        c.setFont("Helvetica", label_font_size)
        c.setFillColor(label_color)
        label_text = _truncate_text(label, "Helvetica", label_font_size, label_width, ellipsis="")
        c.drawString(label_x, text_y, label_text)

        c.setFont("Helvetica", value_font_size)
        c.setFillColor(value_color)
        for line in lines:
            c.drawRightString(value_right, text_y, line)
            text_y -= leading

        current_y = row_bottom

    c.setFillColor(colors.black)
    return y_top - current_y


def _draw_info_block(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    title: str,
    items: List[Tuple[str, str]],
    *,
    min_height: Optional[float] = None,
) -> float:
    header_height = 7 * mm
    padding_x = 3 * mm
    outer_padding = 2 * mm
    row_padding = 2 * mm

    inner_width = width - 2 * padding_x
    layout, _content_height, label_width, value_width, leading = _layout_kv_items(items, inner_width)
    row_height_sum = sum(max(1, len(lines)) * leading + 2 * row_padding for _, lines in layout)
    box_height = header_height + outer_padding * 2 + row_height_sum
    if min_height and box_height < min_height:
        box_height = min_height

    _draw_box(c, x, y_top, width, box_height, stroke_color=GRAY_BORDER)
    _draw_box(c, x, y_top, width, header_height, stroke_color=GRAY_BORDER, fill_color=GRAY_LIGHT)

    title_font = 9
    title_y = y_top - header_height + (header_height - title_font) / 2
    c.setFont("Helvetica-Bold", title_font)
    c.setFillColor(DARK_TEXT)
    c.drawCentredString(x + width / 2, title_y, title)
    c.setFillColor(colors.black)

    content_top = y_top - header_height - outer_padding
    _draw_kv_rows_with_lines(
        c,
        x + padding_x,
        content_top,
        inner_width,
        layout,
        label_width=label_width,
        value_width=value_width,
        leading=leading,
        padding_x=0,
        padding_y=row_padding,
        line_color=GRAY_BORDER,
        label_color=GRAY_TEXT,
        value_color=colors.black,
        label_font_size=8,
        value_font_size=9,
        gap=4,
    )
    return box_height


def _draw_table(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    columns: List[Dict[str, Any]],
    rows: List[Dict[str, str]],
    *,
    max_height: Optional[float] = None,
) -> float:
    header_font_size = 9
    body_font_size = 9
    header_height = 7 * mm
    padding_x = 2 * mm
    padding_y = 1.5 * mm
    leading = body_font_size + 2

    col_widths = [width * col["width"] for col in columns]

    available_body_height = None
    if max_height is not None:
        available_body_height = max(0, max_height - header_height)

    row_layouts: List[Tuple[float, List[List[str]]]] = []
    used_body_height = 0.0

    for row in rows:
        remaining = None
        if available_body_height is not None:
            remaining = max(0, available_body_height - used_body_height)
        max_lines_desc = None
        if remaining is not None:
            max_lines_desc = max(1, int((remaining - 2 * padding_y) // leading))

        cell_lines: List[List[str]] = []
        row_line_count = 1
        for idx, col in enumerate(columns):
            key = col["key"]
            raw_value = row.get(key, "")
            text = raw_value or ""
            cell_width = max(10, col_widths[idx] - 2 * padding_x)
            if col.get("wrap", False):
                lines = _wrap_and_truncate(text, "Helvetica", body_font_size, cell_width, max_lines=max_lines_desc)
            else:
                lines = [_truncate_text(text, "Helvetica", body_font_size, cell_width, ellipsis="")]
            cell_lines.append(lines)
            row_line_count = max(row_line_count, len(lines))

        row_height = row_line_count * leading + 2 * padding_y
        if remaining is not None and row_height > remaining:
            max_lines_desc = max(1, int((remaining - 2 * padding_y) // leading))
            desc_index = next((i for i, col in enumerate(columns) if col.get("wrap", False)), None)
            if desc_index is not None:
                cell_width = max(10, col_widths[desc_index] - 2 * padding_x)
                lines = _wrap_and_truncate(
                    row.get(columns[desc_index]["key"], ""),
                    "Helvetica",
                    body_font_size,
                    cell_width,
                    max_lines=max_lines_desc,
                )
                cell_lines[desc_index] = lines
                row_line_count = max(1, len(lines))
                row_height = row_line_count * leading + 2 * padding_y

        row_layouts.append((row_height, cell_lines))
        used_body_height += row_height

    table_height = header_height + used_body_height

    _draw_box(c, x, y_top, width, table_height, stroke_color=GRAY_BORDER)
    c.setFillColor(GRAY_LIGHT)
    c.rect(x, y_top - header_height, width, header_height, stroke=0, fill=1)
    c.setFillColor(colors.black)

    header_y = y_top - header_height + (header_height - header_font_size) / 2
    col_x = x
    c.setFont("Helvetica-Bold", header_font_size)
    for col, col_width in zip(columns, col_widths):
        align = col.get("align", "left")
        if align == "right":
            c.drawRightString(col_x + col_width - padding_x, header_y, col["label"])
        elif align == "center":
            c.drawCentredString(col_x + col_width / 2, header_y, col["label"])
        else:
            c.drawString(col_x + padding_x, header_y, col["label"])
        col_x += col_width

    current_y = y_top - header_height
    c.setStrokeColor(GRAY_BORDER)
    c.line(x, current_y, x + width, current_y)
    col_x = x
    for col_width in col_widths[:-1]:
        col_x += col_width
        c.line(col_x, y_top, col_x, y_top - table_height)
    for row_height, cell_lines in row_layouts:
        row_top = current_y
        row_bottom = row_top - row_height
        c.line(x, row_bottom, x + width, row_bottom)

        line_top = row_top - padding_y
        col_x = x
        for col, col_width, lines in zip(columns, col_widths, cell_lines):
            align = col.get("align", "left")
            text_x_left = col_x + padding_x
            text_x_right = col_x + col_width - padding_x
            line_y = line_top - body_font_size
            c.setFont("Helvetica", body_font_size)
            for line in lines:
                if align == "right":
                    c.drawRightString(text_x_right, line_y, line)
                elif align == "center":
                    c.drawCentredString(col_x + col_width / 2, line_y, line)
                else:
                    c.drawString(text_x_left, line_y, line)
                line_y -= leading
            col_x += col_width

        current_y -= row_height

    return table_height


def _draw_totals_box(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    items: List[Tuple[str, str]],
) -> float:
    outer_padding = 2 * mm
    row_padding = 2 * mm
    font_size = 9
    leading = font_size + 2
    row_height = leading + 2 * row_padding
    height = outer_padding * 2 + len(items) * row_height

    _draw_box(c, x, y_top, width, height, stroke_color=GRAY_BORDER)

    current_y = y_top - outer_padding
    label_x = x + outer_padding
    value_x = x + width - outer_padding

    for idx, (label, value) in enumerate(items):
        is_total = idx == len(items) - 1
        row_top = current_y
        row_bottom = row_top - row_height
        line_y = row_top - row_padding - font_size
        c.setFont("Helvetica-Bold" if is_total else "Helvetica", font_size)
        c.setFillColor(DARK_TEXT if is_total else GRAY_TEXT)
        c.drawString(label_x, line_y, label)
        c.setFillColor(DARK_TEXT)
        c.drawRightString(value_x, line_y, value)
        if idx < len(items) - 1:
            c.setStrokeColor(GRAY_BORDER)
            c.line(x, row_bottom, x + width, row_bottom)
        current_y = row_bottom

    c.setFillColor(colors.black)
    return height


def _status_color(code: Optional[str], message: Optional[str]) -> colors.Color:
    code_clean = _clean(code) or ""
    message_clean = (message or "").lower()
    if code_clean == "0160":
        return RED_SOFT
    if "acept" in message_clean or "aprob" in message_clean or "ok" in message_clean:
        return GREEN_SOFT
    if code_clean and code_clean.startswith("0"):
        return GREEN_SOFT
    return DARK_TEXT


def _draw_sifen_box(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    items: List[Tuple[str, str, colors.Color]],
) -> float:
    header_height = 6 * mm
    padding_x = 2 * mm
    padding_y = 2 * mm
    label_font_size = 7
    value_font_size = 8
    leading = value_font_size + 1

    labels = [label for label, _, _ in items]
    max_label_width = max((_text_width(label, "Helvetica", label_font_size) for label in labels), default=0)
    label_width = min(max_label_width + 4, width * 0.3)
    value_width = max(10, width - 2 * padding_x - label_width - 4)

    layout: List[Tuple[str, List[str], colors.Color]] = []
    total_lines = 0
    for label, value, color in items:
        lines = _wrap_and_truncate(value, "Helvetica", value_font_size, value_width, max_lines=2)
        layout.append((label, lines, color))
        total_lines += len(lines)

    content_height = total_lines * leading
    box_height = header_height + padding_y * 2 + content_height

    _draw_box(c, x, y_top, width, box_height, stroke_color=GRAY_BORDER)
    _draw_box(c, x, y_top, width, header_height, stroke_color=GRAY_BORDER, fill_color=GRAY_LIGHT)

    title_font = 8
    title_y = y_top - header_height + (header_height - title_font) / 2
    c.setFont("Helvetica-Bold", title_font)
    c.setFillColor(DARK_TEXT)
    c.drawString(x + padding_x, title_y, "RESUMEN SIFEN")
    c.setFillColor(colors.black)

    content_top = y_top - header_height - padding_y
    current_y = content_top
    label_x = x + padding_x
    value_x = label_x + label_width + 4

    for label, lines, color in layout:
        if not lines:
            lines = [_ND]
        line_y = current_y - value_font_size
        c.setFont("Helvetica", label_font_size)
        c.setFillColor(GRAY_TEXT)
        c.drawString(label_x, line_y, label)

        c.setFont("Helvetica", value_font_size)
        c.setFillColor(color)
        c.drawString(value_x, line_y, lines[0])
        current_y -= leading

        for line in lines[1:]:
            line_y = current_y - value_font_size
            c.drawString(value_x, line_y, line)
            current_y -= leading

    c.setFillColor(colors.black)
    return box_height


def _draw_customer_band(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    left_items: List[Tuple[str, str]],
    right_items: List[Tuple[str, str]],
) -> float:
    padding_x = 3 * mm
    row_height = 6.5 * mm
    rows = max(len(left_items), len(right_items))
    height = rows * row_height

    _draw_box(c, x, y_top, width, height, stroke_color=GRAY_BORDER)

    col_gap = 6 * mm
    col_width = (width - col_gap) / 2
    left_x = x
    right_x = x + col_width + col_gap

    label_ratio = 0.42
    label_width = col_width * label_ratio
    value_width = col_width - label_width - 2 * padding_x

    c.setStrokeColor(GRAY_BORDER)
    c.line(x + col_width + col_gap / 2, y_top, x + col_width + col_gap / 2, y_top - height)

    for idx in range(rows):
        row_top = y_top - idx * row_height
        row_bottom = row_top - row_height
        if idx < rows - 1:
            c.line(x, row_bottom, x + width, row_bottom)

        if idx < len(left_items):
            label, value = left_items[idx]
            label_text = _truncate_text(label, "Helvetica", 8, label_width, ellipsis="")
            value_text = _truncate_text(value, "Helvetica", 9, value_width, ellipsis="")
            text_y = row_top - (row_height / 2) - 3
            c.setFont("Helvetica", 8)
            c.setFillColor(GRAY_TEXT)
            c.drawString(left_x + padding_x, text_y, label_text)
            c.setFont("Helvetica", 9)
            c.setFillColor(DARK_TEXT)
            c.drawRightString(left_x + col_width - padding_x, text_y, value_text)

        if idx < len(right_items):
            label, value = right_items[idx]
            label_text = _truncate_text(label, "Helvetica", 8, label_width, ellipsis="")
            value_text = _truncate_text(value, "Helvetica", 9, value_width, ellipsis="")
            text_y = row_top - (row_height / 2) - 3
            c.setFont("Helvetica", 8)
            c.setFillColor(GRAY_TEXT)
            c.drawString(right_x + padding_x, text_y, label_text)
            c.setFont("Helvetica", 9)
            c.setFillColor(DARK_TEXT)
            c.drawRightString(right_x + col_width - padding_x, text_y, value_text)

    c.setFillColor(colors.black)
    return height


def _draw_value_partial_row(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    col_widths: List[float],
    exentas: str,
    grav5: str,
    grav10: str,
) -> float:
    height = 6.5 * mm
    _draw_box(c, x, y_top, width, height, stroke_color=GRAY_BORDER)
    col_x = x
    for col_width in col_widths[:-1]:
        col_x += col_width
        c.line(col_x, y_top, col_x, y_top - height)

    label_x = x + 2 * mm
    text_y = y_top - (height / 2) - 3
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(DARK_TEXT)
    c.drawString(label_x, text_y, "PARCIAL")

    # Place values in the last three columns
    value_cols = [exentas, grav5, grav10]
    col_start = x + sum(col_widths[:3])
    for idx, value in enumerate(value_cols):
        col_width = col_widths[3 + idx]
        c.setFont("Helvetica", 9)
        c.setFillColor(DARK_TEXT)
        c.drawRightString(col_start + col_width - 2 * mm, text_y, value)
        col_start += col_width

    c.setFillColor(colors.black)
    return height


def _draw_totals_footer(
    c: canvas.Canvas,
    x: float,
    y_top: float,
    width: float,
    total: str,
    iva5: str,
    iva10: str,
    total_iva: str,
) -> float:
    row_height = 7 * mm
    total_height = row_height * 2

    _draw_box(c, x, y_top, width, row_height, stroke_color=GRAY_BORDER)
    _draw_box(c, x, y_top - row_height, width, row_height, stroke_color=GRAY_BORDER)

    text_y = y_top - (row_height / 2) - 3
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(DARK_TEXT)
    c.drawString(x + 2 * mm, text_y, "TOTAL A PAGAR")
    c.drawRightString(x + width - 2 * mm, text_y, total)

    text_y2 = y_top - row_height - (row_height / 2) - 3
    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_TEXT)
    c.drawString(x + 2 * mm, text_y2, "LIQUIDACIÓN DE IVA")
    c.setFont("Helvetica", 8)
    c.setFillColor(DARK_TEXT)
    c.drawString(x + width * 0.32, text_y2, f"(5%): {iva5}")
    c.drawString(x + width * 0.55, text_y2, f"(10%): {iva10}")
    c.drawRightString(x + width - 2 * mm, text_y2, f"TOTAL IVA: {total_iva}")

    c.setFillColor(colors.black)
    return total_height

def _extract_items(data: Dict[str, Any], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in ("items", "detalle", "detalles", "detalle_items", "dDetalle"):
        value = parsed.get(key) if isinstance(parsed.get(key), list) else data.get(key)
        if isinstance(value, list):
            return value
    return []


def _map_item(item: Dict[str, Any]) -> Tuple[Dict[str, str], float, float, float]:
    qty = _safe(item.get("cantidad") or item.get("cant") or item.get("dCant"), "")
    desc = _safe(item.get("descripcion") or item.get("desc") or item.get("dDesc"), "")
    unit_raw = item.get("precio_unit") or item.get("precio") or item.get("dPUnIt")
    total_raw = item.get("total") or item.get("dTotOpeItem")
    iva_raw = item.get("iva") or item.get("dTasaIVA") or item.get("iAfecIVA")

    total_num = _to_num(total_raw)
    rate = _normalize_iva_rate(iva_raw)
    exentas = 0.0
    grav5 = 0.0
    grav10 = 0.0
    if rate == 5:
        grav5 = total_num
    elif rate == 10:
        grav10 = total_num
    else:
        exentas = total_num

    row = {
        "cant": qty,
        "descripcion": desc,
        "precio_unit": _fmt_num(unit_raw, fallback=""),
        "exentas": _fmt_num(exentas, fallback="0"),
        "grav5": _fmt_num(grav5, fallback="0"),
        "grav10": _fmt_num(grav10, fallback="0"),
    }
    return row, exentas, grav5, grav10


class _PageNumCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states) or 1
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(page_count)
            super().showPage()
        super().save()

    def _draw_page_number(self, page_count: int) -> None:
        width, _ = self._pagesize
        self.setFont("Helvetica", 8)
        self.setFillColor(GRAY_TEXT)
        self.drawRightString(width - 18 * mm, 12 * mm, f"Página {self._pageNumber} de {page_count}")
        self.setFillColor(colors.black)


def render_invoice_pdf(data: Dict[str, Any], issuer: Dict[str, Any], out_path: Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    parsed = data.get("parsed_fields") if isinstance(data.get("parsed_fields"), dict) else {}
    xml_fields = _extract_xml_fields(_clean(data.get("response_xml")) or "")
    cdc = _extract_cdc(data, parsed)
    qr_override = _clean(data.get("qr_url") or data.get("dCarQR"))
    if qr_override:
        qr_override = qr_override.replace("&amp;", "&")
    kude_qr_value = qr_override or _build_kude_qr_value(cdc)

    doc_series = _get_field(data, parsed, xml_fields, "dSerDoc", "serie", "serie_doc") or _ND
    doc_number = _get_field(data, parsed, xml_fields, "dNumDoc", "numero", "nro") or _ND

    fecha_emision = _get_field(
        data,
        parsed,
        xml_fields,
        "dFecEmi",
        "dFecEm",
        "fecha_emision",
        "fecha",
        "dFecProc",
    ) or _ND

    resumen = {
        "dProtConsLote": _get_field(data, parsed, xml_fields, "dProtConsLote"),
        "dId": _get_field(data, parsed, xml_fields, "dId"),
        "dCodResLot": _get_field(data, parsed, xml_fields, "dCodResLot", "dCodRes"),
        "dMsgResLot": _get_field(data, parsed, xml_fields, "dMsgResLot", "dMsgRes"),
        "dFecProc": _get_field(data, parsed, xml_fields, "dFecProc"),
    }

    endpoint = _first(
        data.get("endpoint"),
        data.get("post_url_final"),
        data.get("post_url"),
        data.get("soap_address"),
    )

    receiver = {
        "nombre": _get_field(data, parsed, xml_fields, "dNomRec", "razon_receptor", "receptor"),
        "ruc": _get_field(data, parsed, xml_fields, "dRucRec", "ruc_receptor"),
        "dv": _get_field(data, parsed, xml_fields, "dDVRec", "dv_receptor"),
        "direccion": _get_field(data, parsed, xml_fields, "dDirRec", "direccion_receptor"),
        "telefono": _get_field(data, parsed, xml_fields, "dTelRec", "telefono_receptor"),
        "email": _get_field(data, parsed, xml_fields, "dEmailRec", "email_receptor"),
    }

    has_receiver = any(_clean(v) for v in receiver.values())

    subtotal = _fmt_num(_get_field(data, parsed, xml_fields, "dTotOpe", "subtotal", "sub_total"), fallback="0")
    iva10 = _fmt_num(_get_field(data, parsed, xml_fields, "dIVA10", "iva10", "iva_10"), fallback="0")
    iva5 = _fmt_num(_get_field(data, parsed, xml_fields, "dIVA5", "iva5", "iva_5"), fallback="0")
    total = _fmt_num(_get_field(data, parsed, xml_fields, "dTotGralOpe", "total", "monto_total"), fallback="0")

    c = _PageNumCanvas(str(out_path), pagesize=A4)
    width, height = A4
    margin = 18 * mm
    x_left = margin
    x_right = width - margin
    content_width = x_right - x_left
    y_top = height - margin

    header_gap = 8 * mm
    header_box_width = min(80 * mm, content_width * 0.42)
    left_width = content_width - header_box_width - header_gap
    if left_width < 80 * mm:
        header_box_width = content_width * 0.38
        left_width = content_width - header_box_width - header_gap

    header_left_height = _draw_header_left(c, x_left, y_top, left_width, issuer)
    issuer_name = _safe(issuer.get("razon_social"))
    right_top_gap = 0
    timbrado_clean = _clean(issuer.get("timbrado"))
    vigencia_clean = _clean(issuer.get("vigencia"))
    if timbrado_clean or vigencia_clean:
        timbrado_vigencia = f"{timbrado_clean or _ND} / {vigencia_clean or _ND}"
    else:
        timbrado_vigencia = _ND

    header_box_height = _draw_header_box(
        c,
        x_left + left_width + header_gap,
        y_top,
        header_box_width,
        "FACTURA",
        [
            ("Serie / Número", f"{doc_series} / {doc_number}"),
            ("Fecha de emisión", fecha_emision),
            ("RUC + DV", _format_ruc_dv(issuer.get("ruc"), issuer.get("dv"))),
            ("Timbrado / Vigencia", timbrado_vigencia),
        ],
    )

    header_height = max(header_left_height, header_box_height)
    y = y_top - header_height - 4 * mm

    ruc_dv_rec = _format_ruc_dv(receiver.get("ruc"), receiver.get("dv"))
    cond_venta = _get_field(
        data,
        parsed,
        xml_fields,
        "dDCondOpe",
        "dCondOpe",
        "condicion_venta",
        "cond_venta",
    )
    if cond_venta:
        cond_venta = cond_venta.upper()
    remision = _get_field(data, parsed, xml_fields, "dNumRem", "dNumRemision", "remision")
    tel_rec = _safe(receiver.get("telefono"))

    left_items = [
        ("Fecha:", _format_date(fecha_emision)),
        ("Cliente:", _safe(receiver.get("nombre"))),
        ("RUC:", ruc_dv_rec),
        ("Dirección:", _safe(receiver.get("direccion"))),
    ]
    right_items = [
        ("Condición de venta:", _safe(cond_venta)),
        ("Remisión:", _safe(remision)),
        ("Teléfono:", _safe(tel_rec)),
    ]

    if has_receiver:
        band_height = _draw_customer_band(c, x_left, y, content_width, left_items, right_items)
        y -= band_height + 6 * mm
    else:
        _draw_hr(c, y, x_left, x_right)
        y -= 6 * mm

    items_raw = _extract_items(data, parsed)
    total_exentas = 0.0
    total_grav5 = 0.0
    total_grav10 = 0.0
    if items_raw:
        rows = []
        for item in items_raw:
            mapped, ex, g5, g10 = _map_item(item)
            rows.append(mapped)
            total_exentas += ex
            total_grav5 += g5
            total_grav10 += g10
    else:
        rows = [
            {
                "cant": "",
                "descripcion": "(Sin ítems: este PDF es demo / consulta lote)",
                "precio_unit": "",
                "exentas": "0",
                "grav5": "0",
                "grav10": "0",
            }
        ]

    columns = [
        {"key": "cant", "label": "CANT.", "width": 0.1, "align": "right"},
        {"key": "descripcion", "label": "DESCRIPCIÓN", "width": 0.45, "align": "left", "wrap": True},
        {"key": "precio_unit", "label": "P. UNITARIO", "width": 0.15, "align": "right"},
        {"key": "exentas", "label": "EXENTAS", "width": 0.1, "align": "right"},
        {"key": "grav5", "label": "5%", "width": 0.1, "align": "right"},
        {"key": "grav10", "label": "10%", "width": 0.1, "align": "right"},
    ]

    footer_top = 16 * mm
    max_table_height = max(40 * mm, y - footer_top - 55 * mm)
    # If IVA values are missing but we have gravadas, compute liquidation.
    iva5_val = _to_num(iva5)
    iva10_val = _to_num(iva10)
    if iva5_val == 0 and total_grav5 > 0:
        iva5_val = total_grav5 / 21
    if iva10_val == 0 and total_grav10 > 0:
        iva10_val = total_grav10 / 11
    iva5 = _fmt_num(iva5_val, fallback="0")
    iva10 = _fmt_num(iva10_val, fallback="0")

    table_height = _draw_table(c, x_left, y, content_width, columns, rows, max_height=max_table_height)
    y -= table_height

    col_widths = [content_width * col["width"] for col in columns]
    partial_height = _draw_value_partial_row(
        c,
        x_left,
        y,
        content_width,
        col_widths,
        _fmt_num(total_exentas, fallback="0"),
        _fmt_num(total_grav5, fallback="0"),
        _fmt_num(total_grav10, fallback="0"),
    )
    y -= partial_height + 4 * mm

    total_iva = _fmt_num(_to_num(iva5) + _to_num(iva10), fallback="0")
    totals_height = _draw_totals_footer(c, x_left, y, content_width, total, iva5, iva10, total_iva)
    y -= totals_height + 6 * mm

    qr_size = 28 * mm
    qr_padding = 2 * mm
    label_gap = 1.5 * mm
    label_font_size = 7
    label_leading = 8

    label_lines = ["KUDE"]
    hash_tail = _qr_hash_tail(data.get("qr_url") or data.get("dCarQR"))
    if hash_tail:
        label_lines.append(f"...{hash_tail}")
    else:
        cdc_tail = None
        if cdc:
            cdc_clean = cdc.strip()
            if cdc_clean:
                if len(cdc_clean) >= 10:
                    tail_len = 10
                elif len(cdc_clean) >= 8:
                    tail_len = 8
                else:
                    tail_len = len(cdc_clean)
                cdc_tail = cdc_clean[-tail_len:] if tail_len else None
        if cdc_tail:
            label_lines.append(f"...{cdc_tail}")
    ruc_label = _format_ruc_dv(receiver.get("ruc"), receiver.get("dv"))
    if ruc_label and ruc_label != _ND:
        label_lines.append(f"RUC: {ruc_label}")

    qr_block_height = qr_padding + qr_size + label_gap + len(label_lines) * label_leading
    qr_y_top = y
    qr_x = x_left + qr_padding
    qr_y = qr_y_top - qr_padding - qr_size
    _draw_qr(c, qr_x, qr_y, qr_size, kude_qr_value)

    label_y_top = qr_y - label_gap
    _draw_lines(
        c,
        qr_x,
        label_y_top,
        label_lines,
        "Helvetica",
        label_font_size,
        label_leading,
        GRAY_TEXT,
        width=qr_size,
        align="center",
    )

    y -= qr_block_height + 6 * mm

    # Resumen SIFEN eliminado por requerimiento del cliente.

    _draw_hr(c, footer_top, x_left, x_right)
    c.setFont("Helvetica", 7)
    c.setFillColor(GRAY_TEXT)
    c.drawString(x_left, 10 * mm, "Documento generado automáticamente")
    c.setFillColor(colors.black)

    c.showPage()
    c.save()
