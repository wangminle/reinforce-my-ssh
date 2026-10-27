#!/usr/bin/env python3
"""task-list.md 台账门禁（`check`）：预览级 Markdown 与台账一致性检查。

规则（对照 CLAUDE.md）：
- 表内空行 / 游离的表格行必须失败；
- 表格单元格裸 HTML 必须失败（反引号内的示例代码除外）；
- 反引号未按 CommonMark 闭合（行内奇数个反引号）必须失败；
- 围栏代码块里的示例表格不算真实表；
- 台账一致性：ID 唯一、动作/状态枚举合法、时间格式合法、列数一致、
  章节不重复、[[ID]] 引用不悬空。

用法：python3 tests/check-task-list.py [台账路径，默认 task-list.md]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = {"修复", "开发", "优化", "调整", "规划", "检查", "文档", "运维"}
STATUSES = {"待修复", "待办", "待开发", "进行中", "已完成", "已修复", "已关闭", "已解决", "-"}
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
HTML_RE = re.compile(r"</?[A-Za-z][^>]*>")


def split_cells(line):
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", text)]


def strip_code_span(cell):
    return re.sub(r"`[^`]*`", "", cell)


def check(text, path):
    errors = []
    warnings = []
    lines = text.splitlines()

    # 1) 行内反引号闭合（按行，围栏外）
    fence = None
    body = []
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence = None if fence else stripped[:3]
            continue
        if fence:
            continue
        body.append((number, line))
        if line.count("`") % 2:
            errors.append("%s:%d 行内反引号数量为奇数（未闭合）" % (path, number))

    # 2) 表格结构：分块解析，检测游离行、空行、列数
    tables = []
    current = None
    for number, line in body:
        if line.strip().startswith("|"):
            if current is None:
                current = {"start": number, "rows": []}
            current["rows"].append((number, line))
        else:
            if current is not None:
                tables.append(current)
                current = None
    if current is not None:
        tables.append(current)

    for table in tables:
        rows = table["rows"]
        if len(rows) < 2:
            errors.append("%s:%d 表格缺少分隔行" % (path, rows[0][0]))
            continue
        header_cells = split_cells(rows[0][1])
        separator = split_cells(rows[1][1])
        if not all(set(cell) <= set("-: ") and cell for cell in separator):
            errors.append("%s:%d 表格第二行不是合法分隔行" % (path, rows[1][0]))
        for number, line in rows:
            cells = split_cells(line)
            if len(cells) != len(header_cells):
                errors.append("%s:%d 表格列数 %d 与表头 %d 不一致" % (path, number, len(cells), len(header_cells)))
            for cell in cells:
                if HTML_RE.search(strip_code_span(cell)):
                    errors.append("%s:%d 单元格含裸 HTML：%s" % (path, number, cell[:40]))

    # 3) 章节不重复
    headings = {}
    for number, line in body:
        if line.startswith("## "):
            name = line[3:].strip()
            if name in headings:
                errors.append("%s:%d 章节重复：%s（另见第 %d 行）" % (path, number, name, headings[name]))
            headings[name] = number

    # 4) 台账一致性：ID 唯一、枚举、时间、悬空引用
    known = {}
    references = []
    for table in tables:
        header_cells = split_cells(table["rows"][0][1])
        if "ID" not in header_cells:
            continue
        columns = {name: index for index, name in enumerate(header_cells)}
        for number, line in table["rows"][2:]:
            cells = split_cells(line)
            if len(cells) != len(header_cells):
                continue
            ident = cells[columns["ID"]]
            if not re.fullmatch(r"(BUG|ADJ|DEV|TST|DOC|OPS|CHK)-\d{3}", ident):
                errors.append("%s:%d 非法 ID：%s" % (path, number, ident))
                continue
            if ident in known:
                errors.append("%s:%d 重复 ID：%s（首次见第 %d 行）" % (path, number, ident, known[ident]))
            known[ident] = number
            if "动作" in columns:
                action = cells[columns["动作"]]
                if action not in ACTIONS:
                    errors.append("%s:%d 动作枚举非法：%s" % (path, number, action))
            if "状态" in columns:
                status = cells[columns["状态"]]
                if status not in STATUSES:
                    errors.append("%s:%d 状态枚举非法：%s" % (path, number, status))
            for column in ("发现时间", "完成时间"):
                if column in columns:
                    value = cells[columns[column]]
                    if value != "-" and not TIME_RE.fullmatch(value):
                        errors.append("%s:%d %s 格式非法：%s" % (path, number, column, value))
            if "备注" in columns:
                for match in re.findall(r"\[\[([A-Z]+-\d{3})\]\]", cells[columns["备注"]]):
                    references.append((number, match))
            if "问题描述" in columns:
                for match in re.findall(r"\[\[([A-Z]+-\d{3})\]\]", cells[columns["问题描述"]]):
                    references.append((number, match))
            if "事项" in columns:
                for match in re.findall(r"\[\[([A-Z]+-\d{3})\]\]", cells[columns["事项"]]):
                    references.append((number, match))
    for number, target in references:
        if target not in known:
            errors.append("%s:%d 悬空引用：[[%s]] 未定义" % (path, number, target))

    return errors, warnings


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    path = Path(argv[0]) if argv else ROOT / "task-list.md"
    target = path if path.is_absolute() else ROOT / path
    text = target.read_text(encoding="utf-8")
    errors, warnings = check(text, str(path))
    for warning in warnings:
        print("WARN " + warning)
    for error in errors:
        print("FAIL " + error)
    ids = len(set(re.findall(r"(?:BUG|ADJ|DEV|TST|DOC|OPS|CHK)-\d{3}", text)))
    if errors:
        print("台账门禁失败：%d 个问题（识别 %d 个 ID）" % (len(errors), ids))
        return 1
    print("台账门禁通过：未发现表内空行/裸 HTML/未闭合反引号/ID 或枚举问题（识别 %d 个 ID）" % ids)
    return 0


if __name__ == "__main__":
    sys.exit(main())