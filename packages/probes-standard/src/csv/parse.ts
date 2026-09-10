/** Strict bounded CSV; preserve field prefixes and quoted newlines verbatim. */
export function parseCsv(text: string, delimiter: string): string[][] {
  if (![",", ";", "\t"].includes(delimiter) || text.length > 16384) throw new Error("CSV limit or delimiter");
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let state: "start" | "plain" | "quoted" | "closed" = "start";
  const endField = () => {
    row.push(field);
    if (row.length > 128) throw new Error("CSV column limit");
    field = ""; state = "start";
  };
  const endRow = () => {
    endField(); rows.push(row); row = [];
    if (rows.length > 1000) throw new Error("CSV row limit");
  };
  text = text.replace(/^\uFEFF/, "");
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    if (state === "quoted") {
      if (char === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else state = "closed";
      } else field += char;
    } else if (char === delimiter) endField();
    else if (char === "\r" || char === "\n") {
      if (char === "\r" && text[i + 1] === "\n") i++;
      endRow();
    } else if (char === '"' && state === "start") state = "quoted";
    else {
      if (state === "closed" || char === '"' || char === "\0") throw new Error("Malformed CSV");
      field += char; state = "plain";
    }
  }
  if (state === "quoted") throw new Error("Unterminated CSV field");
  if (state !== "start" || row.length || field) endRow();
  if (!rows.length || rows.some((r) => r.length !== rows[0]!.length)) throw new Error("Empty or ragged CSV");
  return rows;
}
