use super::PublishedPageMeta;

pub fn render_index_html(meta: &PublishedPageMeta) -> String {
    let title = escape_html(&meta.title);
    let description = escape_html(
        meta.description
            .as_deref()
            .unwrap_or("Published domain scan"),
    );
    let scan_time = escape_html(&meta.scan_finished_at);
    let result_count = meta.result_count;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <meta name="description" content="{description}">
    <style>
        :root {{
            --bg: #f7f8f3;
            --panel: #ffffff;
            --text: #17211b;
            --muted: #66756b;
            --line: #dde4dc;
            --accent: #0f766e;
            --accent-soft: #d9f4ef;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(15,118,110,0.10), transparent 28rem),
                linear-gradient(180deg, #fbfcf8 0%, var(--bg) 100%);
            color: var(--text);
        }}

        .wrap {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 32px 20px 48px;
        }}

        .hero {{
            background: rgba(255,255,255,0.84);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(221,228,220,0.9);
            border-radius: 28px;
            padding: 28px;
            box-shadow: 0 18px 60px rgba(23,33,27,0.08);
        }}

        .eyebrow {{
            display: inline-block;
            margin-bottom: 12px;
            padding: 6px 10px;
            border-radius: 999px;
            background: var(--accent-soft);
            color: var(--accent);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }}

        h1 {{
            margin: 0;
            font-size: clamp(2rem, 5vw, 3.4rem);
            line-height: 1.04;
        }}

        .description {{
            max-width: 58rem;
            margin: 14px 0 0;
            color: var(--muted);
            font-size: 1rem;
            line-height: 1.7;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-top: 22px;
        }}

        .stat {{
            padding: 16px 18px;
            border-radius: 18px;
            border: 1px solid var(--line);
            background: var(--panel);
        }}

        .stat-label {{
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .stat-value {{
            margin-top: 8px;
            font-size: 1.5rem;
            font-weight: 700;
        }}

        .results {{
            margin-top: 24px;
            background: var(--panel);
            border-radius: 28px;
            border: 1px solid var(--line);
            box-shadow: 0 18px 60px rgba(23,33,27,0.06);
            overflow: hidden;
        }}

        .results-head {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            border-bottom: 1px solid var(--line);
        }}

        .results-title {{
            margin: 0;
            font-size: 1.1rem;
        }}

        .search {{
            width: min(320px, 100%);
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid var(--line);
            font-size: 0.95rem;
            outline: none;
        }}

        .search:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 4px rgba(15,118,110,0.10);
        }}

        .domain-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
            padding: 24px;
        }}

        .domain-card {{
            padding: 16px 20px;
            border-radius: 20px;
            border: 1px solid #eef2ed;
            background: #fff;
            transition: all 0.2s ease;
            position: relative;
        }}

        .domain-card:hover {{
            border-color: var(--accent);
            box-shadow: 0 4px 20px rgba(15,118,110,0.06);
            transform: translateY(-2px);
        }}

        .domain-name {{
            font-size: 1.1rem;
            font-weight: 800;
            color: var(--text);
            margin-bottom: 8px;
            display: block;
            word-break: break-all;
        }}

        .meta-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}

        .badge {{
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 4px 10px;
            border-radius: 8px;
        }}

        .badge-sig {{
            background: var(--accent-soft);
            color: var(--accent);
        }}

        .badge-exp {{
            background: #f1f5f9;
            color: #64748b;
        }}

        .domain-card .action-btn {{
            position: absolute;
            top: 14px;
            right: 14px;
            opacity: 0;
            transition: opacity 0.2s;
        }}

        .domain-card:hover .action-btn {{
            opacity: 1;
        }}

        .empty {{
            grid-column: 1 / -1;
            padding: 48px;
            text-align: center;
            color: var(--muted);
        }}

        .footer {{
            margin-top: 16px;
            color: var(--muted);
            font-size: 0.9rem;
        }}

        @media (max-width: 720px) {{
            .wrap {{
                padding: 20px 14px 28px;
            }}

            .hero, .results {{
                border-radius: 22px;
            }}
        }}
    </style>
</head>
<body>
    <div class="wrap">
        <section class="hero">
            <span class="eyebrow">Published Scan</span>
            <h1>{title}</h1>
            <p class="description">{description}</p>
            <div class="stats">
                <div class="stat">
                    <div class="stat-label">Available Domains</div>
                    <div class="stat-value">{result_count}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Scan Time</div>
                    <div class="stat-value" style="font-size:1rem">{scan_time}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Slug</div>
                    <div class="stat-value" style="font-size:1rem">{slug}</div>
                </div>
            </div>
        </section>

        <section class="results">
            <div class="results-head">
                <div>
                    <h2 class="results-title">Available Domain List</h2>
                    <div class="footer" id="summary">Loading published data...</div>
                </div>
                <input id="search" class="search" type="search" placeholder="Filter domains">
            </div>
            <div id="rows" class="domain-grid">
                <div class="empty">Loading datasets...</div>
            </div>
            <div id="load-more-container" style="display:none; padding: 24px; text-align: center; border-top: 1px solid var(--line);">
                <button id="load-more" style="padding: 12px 32px; border-radius: 16px; border: 1px solid var(--line); background: var(--panel); cursor: pointer; font-weight: 700; color: var(--accent); transition: all 0.2s;">Show More Domains</button>
            </div>
        </section>
    </div>

    <script>
        const state = {{ rows: [], visibleCount: 500, searchTimeout: null }};
        const rowsEl = document.getElementById('rows');
        const summaryEl = document.getElementById('summary');
        const searchEl = document.getElementById('search');
        const loadMoreBtn = document.getElementById('load-more');
        const loadMoreContainer = document.getElementById('load-more-container');

        const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({{
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }})[char]);

        const render = () => {{
            const query = searchEl.value.trim().toLowerCase();
            const filtered = query
                ? state.rows.filter((row) => row._queryTarget.includes(query))
                : state.rows;

            const visibleResults = filtered.slice(0, state.visibleCount);
            summaryEl.textContent = `${{visibleResults.length}} of ${{filtered.length}} matching domains (${{state.rows.length}} total)`;

            if (filtered.length === 0) {{
                rowsEl.innerHTML = '<div class="empty">No domains matched the current filter.</div>';
                loadMoreContainer.style.display = 'none';
                return;
            }}

            rowsEl.innerHTML = visibleResults.map((row) => {{
                let metaHtml = '';
                if (row.signatures) {{
                    metaHtml += `<span class="badge badge-sig">${{escapeHtml(row.signatures)}}</span>`;
                }}
                if (row.expiration_date) {{
                    metaHtml += `<span class="badge badge-exp">${{escapeHtml(row.expiration_date)}}</span>`;
                }}

                return `
                    <div class="domain-card">
                        <span class="domain-name">${{escapeHtml(row.domain)}}</span>
                        <div class="meta-tags">${{metaHtml}}</div>
                        <a href="https://porkbun.com/checkout/search?q=${{row.domain}}" target="_blank" class="action-btn">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent)"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                        </a>
                    </div>
                `;
            }}).join('');

            loadMoreContainer.style.display = visibleResults.length < filtered.length ? 'block' : 'none';
        }};

        const debouncedRender = () => {{
            if (state.searchTimeout) clearTimeout(state.searchTimeout);
            state.searchTimeout = setTimeout(render, 300);
        }};

        searchEl.addEventListener('input', () => {{
            state.visibleCount = 500;
            debouncedRender();
        }});

        loadMoreBtn.addEventListener('click', () => {{
            state.visibleCount += 500;
            render();
        }});

        fetch('./data.json')
            .then((response) => response.json())
            .then((payload) => {{
                state.rows = Array.isArray(payload.domains) 
                    ? payload.domains.map(r => ({{ ...r, _queryTarget: r.domain.toLowerCase() }})) 
                    : [];
                render();
            }})
            .catch(() => {{
                rowsEl.innerHTML = '<div class="empty">Failed to load published data.</div>';
                summaryEl.textContent = 'Data unavailable';
            }});
    </script>
</body>
</html>
"#,
        slug = escape_html(&meta.slug),
    )
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_index_html_escapes_title_and_description() {
        let html = render_index_html(&PublishedPageMeta {
            id: "id-1".to_string(),
            slug: "scan-1".to_string(),
            scan_id: "scan-id".to_string(),
            title: "<unsafe>".to_string(),
            description: Some("\"quoted\"".to_string()),
            suffix: ".com".to_string(),
            pattern: "a".to_string(),
            length: 4,
            result_count: 3,
            published_at: "2026-04-21T12:00:00Z".to_string(),
            scan_finished_at: "2026-04-21T12:00:00Z".to_string(),
            updated_at: "2026-04-21T12:00:00Z".to_string(),
        });

        assert!(html.contains("&lt;unsafe&gt;"));
        assert!(html.contains("&quot;quoted&quot;"));
        assert!(!html.contains("<unsafe>"));
    }
}
