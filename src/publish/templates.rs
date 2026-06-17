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
            --accent-hover: #0d645d;
            --danger: #ef4444;
            --danger-soft: rgba(239, 68, 68, 0.08);
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
            max-width: 1200px;
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

        /* Main layout layout split */
        .main-layout {{
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 28px;
            margin-top: 28px;
            align-items: start;
        }}

        /* Sidebar styles */
        .sidebar {{
            background: rgba(255,255,255,0.84);
            backdrop-filter: blur(8px);
            border: 1px solid var(--line);
            border-radius: 28px;
            padding: 24px;
            box-shadow: 0 18px 60px rgba(23,33,27,0.04);
            position: sticky;
            top: 24px;
        }}

        .sidebar-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .sidebar-title {{
            margin: 0;
            font-size: 1.2rem;
            font-weight: 800;
            color: var(--accent);
        }}

        .filter-group {{
            margin-bottom: 20px;
        }}

        .filter-group label {{
            display: block;
            margin-bottom: 8px;
            font-size: 11px;
            font-weight: 700;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .search-mode-tabs {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            background: var(--bg);
            padding: 4px;
            border-radius: 12px;
            border: 1px solid var(--line);
        }}

        .tab-btn {{
            background: transparent;
            border: none;
            padding: 8px 0;
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--muted);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .tab-btn:hover {{
            color: var(--text);
        }}

        .tab-btn.active {{
            background: var(--panel);
            color: var(--accent);
            box-shadow: 0 2px 8px rgba(23,33,27,0.06);
        }}

        .search-input {{
            width: 100%;
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid var(--line);
            font-size: 0.95rem;
            outline: none;
            background: var(--panel);
            color: var(--text);
            transition: all 0.2s ease;
        }}

        .search-input:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 4px var(--accent-soft);
        }}

        .search-input.invalid {{
            border-color: var(--danger);
            box-shadow: 0 0 0 4px var(--danger-soft);
        }}

        .pattern-chips {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
        }}

        .chip {{
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 8px 0;
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--text);
            cursor: pointer;
            text-align: center;
            transition: all 0.2s ease;
        }}

        .chip:hover {{
            border-color: var(--accent);
            color: var(--accent);
        }}

        .chip.active {{
            background: var(--accent-soft);
            border-color: var(--accent);
            color: var(--accent);
        }}

        .checkbox-group {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .checkbox-label {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            color: var(--text);
            cursor: pointer;
        }}

        .checkbox-label input {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
            border: 1px solid var(--line);
            accent-color: var(--accent);
            cursor: pointer;
        }}

        .error-msg {{
            color: var(--danger);
            font-size: 0.8rem;
            margin-top: 6px;
            display: none;
        }}

        .sidebar-actions {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 10px;
            margin-top: 24px;
        }}

        .action-btn-primary {{
            background: var(--accent);
            border: none;
            border-radius: 14px;
            color: white;
            padding: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(15,118,110,0.15);
            text-align: center;
            text-decoration: none;
        }}

        .action-btn-primary:hover {{
            background: var(--accent-hover);
            transform: translateY(-1px);
        }}

        .action-btn-secondary {{
            background: transparent;
            border: 1px solid var(--line);
            border-radius: 14px;
            color: var(--text);
            padding: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
            text-align: center;
        }}

        .action-btn-secondary:hover {{
            background: var(--bg);
            border-color: var(--muted);
        }}

        /* Content list styles */
        .content {{
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
            font-weight: 800;
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
            margin-top: 6px;
            color: var(--muted);
            font-size: 0.9rem;
        }}

        /* Mobile controls UI */
        .mobile-toggle-btn {{
            display: none;
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 10px 18px;
            border-radius: 12px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .mobile-toggle-btn:hover {{
            background: var(--accent-hover);
        }}

        .mobile-close-btn {{
            display: none;
            background: transparent;
            border: 1px solid var(--line);
            padding: 6px 12px;
            border-radius: 8px;
            font-weight: 700;
            cursor: pointer;
            color: var(--muted);
        }}

        @media (max-width: 860px) {{
            .wrap {{
                padding: 20px 14px 28px;
            }}

            .hero, .content {{
                border-radius: 22px;
            }}

            .main-layout {{
                grid-template-columns: 1fr;
            }}

            .sidebar {{
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                z-index: 9999;
                border-radius: 0;
                border: none;
                overflow-y: auto;
                background: #fff;
            }}

            .sidebar.open {{
                display: block;
            }}

            .mobile-toggle-btn {{
                display: block;
            }}

            .mobile-close-btn {{
                display: block;
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

        <div class="main-layout">
            <!-- Sidebar filters -->
            <aside id="sidebar" class="sidebar">
                <div class="sidebar-header">
                    <h2 class="sidebar-title">Filters / 筛选</h2>
                    <button type="button" id="btn-toggle-filters-mobile" class="mobile-close-btn">Hide / 隐藏</button>
                </div>
                
                <div class="filter-group">
                    <label>Search Mode / 检索模式</label>
                    <div class="search-mode-tabs">
                        <button type="button" class="tab-btn active" data-mode="text">Text</button>
                        <button type="button" class="tab-btn" data-mode="wildcard">Wildcard</button>
                        <button type="button" class="tab-btn" data-mode="regex">Regex</button>
                    </div>
                </div>

                <div class="filter-group">
                    <label for="search">Pattern / 关键词</label>
                    <input id="search" class="search-input" type="search" placeholder="Filter domains... / 输入关键词筛选...">
                    <div id="regex-error" class="error-msg"></div>
                </div>

                <div class="filter-group">
                    <label>Structure / 常见结构</label>
                    <div class="pattern-chips">
                        <button type="button" class="chip" data-pattern="AAAA">AAAA</button>
                        <button type="button" class="chip" data-pattern="AABB">AABB</button>
                        <button type="button" class="chip" data-pattern="ABAB">ABAB</button>
                        <button type="button" class="chip" data-pattern="ABBA">ABBA</button>
                        <button type="button" class="chip" data-pattern="AAAB">AAAB</button>
                        <button type="button" class="chip" data-pattern="ABBB">ABBB</button>
                    </div>
                </div>

                <div class="filter-group">
                    <label for="exclude">Exclusions / 排除字符</label>
                    <input id="exclude" class="search-input" type="text" placeholder="e.g. j, q, x, z / 排除字符如 j, q, x, z">
                </div>

                <div class="filter-group">
                    <label>Composition / 字符特征</label>
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="filter-vowels-only"> Only Vowels (仅元音)
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="filter-consonants-only"> Only Consonants (仅辅音)
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="filter-no-vowels"> No Vowels (排除元音)
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="filter-alternating"> Alternating (元辅交替)
                        </label>
                    </div>
                </div>

                <div class="sidebar-actions">
                    <button type="button" id="btn-export" class="action-btn-primary">Download Domain List / 下载域名列表 (TXT)</button>
                    <button type="button" id="btn-reset" class="action-btn-secondary">Reset Filters / 重置筛选</button>
                </div>
            </aside>

            <!-- Main results content -->
            <main class="content">
                <div class="results-head">
                    <div>
                        <h2 class="results-title">Available Domain List / 可用域名列表</h2>
                        <div class="footer" id="summary">Loading published data / 正在加载数据...</div>
                    </div>
                    <button type="button" id="btn-toggle-filters-mobile-trigger" class="mobile-toggle-btn">Show Filters / 显示筛选</button>
                </div>
                <div id="rows" class="domain-grid">
                    <div class="empty">Loading datasets...</div>
                </div>
                <div id="load-more-container" style="display:none; padding: 24px; text-align: center; border-top: 1px solid var(--line);">
                    <button id="load-more" class="action-btn-secondary" style="padding: 12px 32px; border-radius: 16px; cursor: pointer; font-weight: 700; color: var(--accent); transition: all 0.2s;">Show More Domains</button>
                </div>
            </main>
        </div>
    </div>

    <script>
        const state = {{ rows: [], visibleCount: 500, searchTimeout: null }};
        const rowsEl = document.getElementById('rows');
        const summaryEl = document.getElementById('summary');
        
        // Filter inputs
        const searchEl = document.getElementById('search');
        const searchModeBtns = document.querySelectorAll('.search-mode-tabs .tab-btn');
        const patternChips = document.querySelectorAll('.pattern-chips .chip');
        const excludeEl = document.getElementById('exclude');
        
        const vowelsOnlyEl = document.getElementById('filter-vowels-only');
        const consonantsOnlyEl = document.getElementById('filter-consonants-only');
        const noVowelsEl = document.getElementById('filter-no-vowels');
        const alternatingEl = document.getElementById('filter-alternating');
        
        const resetBtn = document.getElementById('btn-reset');
        const exportBtn = document.getElementById('btn-export');
        const regexErrorEl = document.getElementById('regex-error');
        
        const loadMoreBtn = document.getElementById('load-more');
        const loadMoreContainer = document.getElementById('load-more-container');
        
        // Mobile sidebar elements
        const sidebarEl = document.getElementById('sidebar');
        const toggleMobileTrigger = document.getElementById('btn-toggle-filters-mobile-trigger');
        const closeMobileBtn = document.getElementById('btn-toggle-filters-mobile');

        // State helper values
        let searchMode = 'text';

        const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({{
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }})[char]);

        const spaceshipSearchUrl = (domain) => `https://www.spaceship.com/domain-search/?query=${{encodeURIComponent(domain)}}`;

        // Helper to convert wildcard to regex
        const wildcardToRegex = (wildcard) => {{
            let regexStr = '^' + wildcard
                .replace(/[-\/\\^$+.()|[\]{{}}]/g, '\\$&')
                .replace(/\*/g, '.*')
                .replace(/\?/g, '.') + '$';
            return new RegExp(regexStr, 'i');
        }};

        // Open/close mobile filters
        if (toggleMobileTrigger) {{
            toggleMobileTrigger.addEventListener('click', () => sidebarEl.classList.add('open'));
        }}
        if (closeMobileBtn) {{
            closeMobileBtn.addEventListener('click', () => sidebarEl.classList.remove('open'));
        }}

        // Mode tabs toggles
        searchModeBtns.forEach(btn => {{
            btn.addEventListener('click', () => {{
                searchModeBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                searchMode = btn.dataset.mode;
                state.visibleCount = 500;
                debouncedRender();
            }});
        }});

        // Pattern chips toggles
        patternChips.forEach(chip => {{
            chip.addEventListener('click', () => {{
                chip.classList.toggle('active');
                state.visibleCount = 500;
                debouncedRender();
            }});
        }});

        // Other inputs listeners
        const inputTriggerList = [searchEl, excludeEl, vowelsOnlyEl, consonantsOnlyEl, noVowelsEl, alternatingEl];
        inputTriggerList.forEach(el => {{
            if (el) {{
                el.addEventListener('input', () => {{
                    state.visibleCount = 500;
                    debouncedRender();
                }});
                if (el.type === 'checkbox') {{
                    el.addEventListener('change', () => {{
                        state.visibleCount = 500;
                        debouncedRender();
                    }});
                }}
            }}
        }});

        // Reset button
        resetBtn.addEventListener('click', () => {{
            searchEl.value = '';
            excludeEl.value = '';
            vowelsOnlyEl.checked = false;
            consonantsOnlyEl.checked = false;
            noVowelsEl.checked = false;
            alternatingEl.checked = false;
            patternChips.forEach(c => c.classList.remove('active'));
            searchModeBtns.forEach(b => b.classList.remove('active'));
            searchModeBtns[0].classList.add('active');
            searchMode = 'text';
            regexErrorEl.style.display = 'none';
            searchEl.classList.remove('invalid');
            state.visibleCount = 500;
            render();
        }});

        // Get list of matching domains
        const getFilteredList = () => {{
            const query = searchEl.value.trim();
            const excludeChars = excludeEl.value.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
            const activePatterns = Array.from(document.querySelectorAll('.pattern-chips .chip.active')).map(c => c.dataset.pattern);
            
            const vowelsOnly = vowelsOnlyEl.checked;
            const consonantsOnly = consonantsOnlyEl.checked;
            const noVowels = noVowelsEl.checked;
            const alternating = alternatingEl.checked;

            let filterFn = () => true;
            
            if (query) {{
                if (searchMode === 'text') {{
                    const queryLower = query.toLowerCase();
                    filterFn = (row) => row._queryTarget.includes(queryLower);
                }} else if (searchMode === 'wildcard') {{
                    try {{
                        const regex = wildcardToRegex(query);
                        filterFn = (row) => regex.test(row.domain);
                        regexErrorEl.style.display = 'none';
                        searchEl.classList.remove('invalid');
                    }} catch (e) {{
                        regexErrorEl.textContent = 'Invalid wildcard pattern / 通配符格式错误';
                        regexErrorEl.style.display = 'block';
                        searchEl.classList.add('invalid');
                        return [];
                    }}
                }} else if (searchMode === 'regex') {{
                    try {{
                        const regex = new RegExp(query, 'i');
                        filterFn = (row) => regex.test(row.domain);
                        regexErrorEl.style.display = 'none';
                        searchEl.classList.remove('invalid');
                    }} catch (e) {{
                        regexErrorEl.textContent = 'Invalid regex / 正则表达式错误: ' + e.message;
                        regexErrorEl.style.display = 'block';
                        searchEl.classList.add('invalid');
                        return [];
                    }}
                }}
            }} else {{
                regexErrorEl.style.display = 'none';
                searchEl.classList.remove('invalid');
            }}

            return state.rows.filter((row) => {{
                if (!filterFn(row)) return false;

                if (excludeChars) {{
                    for (const char of excludeChars) {{
                        if (row._label.includes(char)) return false;
                    }}
                }}

                if (activePatterns.length > 0) {{
                    if (!activePatterns.includes(row._pattern)) return false;
                }}

                if (vowelsOnly && !row._isVowelOnly) return false;
                if (consonantsOnly && !row._isConsonantOnly) return false;
                if (noVowels && row._hasVowel) return false;
                if (alternating && !row._isAlternating) return false;

                return true;
            }});
        }};

        // Download matching list as TXT
        exportBtn.addEventListener('click', () => {{
            const filtered = getFilteredList();
            if (filtered.length === 0) {{
                alert('No matching domains to download! / 没有符合筛选条件的域名可供下载！');
                return;
            }}
            const text = filtered.map(r => r.domain).join('\\r\\n');
            const blob = new Blob([text], {{ type: 'text/plain;charset=utf-8' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `{slug}_filtered_${{filtered.length}}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            const originalText = exportBtn.textContent;
            exportBtn.textContent = '✓ 已下载 ' + filtered.length + ' 个域名';
            exportBtn.style.background = 'var(--accent-hover)';
            setTimeout(() => {{
                exportBtn.textContent = originalText;
                exportBtn.style.background = '';
            }}, 2000);
        }});

        const render = () => {{
            const filtered = getFilteredList();
            const visibleResults = filtered.slice(0, state.visibleCount);
            summaryEl.textContent = `${{visibleResults.length}} of ${{filtered.length}} matching (${{state.rows.length}} total) / ${{visibleResults.length}} / ${{filtered.length}} 个匹配 (共 ${{state.rows.length}} 个)`;

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
                        <a href="${{spaceshipSearchUrl(row.domain)}}" target="_blank" rel="noopener noreferrer" class="action-btn" title="Search on Spaceship" aria-label="Search ${{escapeHtml(row.domain)}} on Spaceship">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent)"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                        </a>
                    </div>
                `;
            }}).join('');

            loadMoreContainer.style.display = visibleResults.length < filtered.length ? 'block' : 'none';
        }};

        const debouncedRender = () => {{
            if (state.searchTimeout) clearTimeout(state.searchTimeout);
            state.searchTimeout = setTimeout(render, 150);
        }};

        loadMoreBtn.addEventListener('click', () => {{
            state.visibleCount += 500;
            render();
        }});

        fetch('./data.json')
            .then((response) => response.json())
            .then((payload) => {{
                const vowels = new Set(['a', 'e', 'i', 'o', 'u']);
                state.rows = Array.isArray(payload.domains) 
                    ? payload.domains.map(r => {{
                        const domainLower = r.domain.toLowerCase();
                        const label = domainLower.split('.')[0];
                        
                        // Precompute vowel/consonant stats
                        let vowelCount = 0;
                        let consonantCount = 0;
                        let hasVowel = false;
                        for (const char of label) {{
                            if (char >= 'a' && char <= 'z') {{
                                if (vowels.has(char)) {{
                                    vowelCount++;
                                    hasVowel = true;
                                }} else {{
                                    consonantCount++;
                                }}
                            }}
                        }}
                        const isVowelOnly = vowelCount === label.length;
                        const isConsonantOnly = consonantCount === label.length;
                        
                        // Precompute alternating
                        let isAlternating = true;
                        if (label.length > 1) {{
                            let prevIsVowel = vowels.has(label[0]);
                            for (let i = 1; i < label.length; i++) {{
                                let currentIsVowel = vowels.has(label[i]);
                                if (currentIsVowel === prevIsVowel) {{
                                    isAlternating = false;
                                    break;
                                }}
                                prevIsVowel = currentIsVowel;
                            }}
                        }} else {{
                            isAlternating = false;
                        }}

                        // Precompute structural pattern (e.g., abba -> ABBA)
                        const map = new Map();
                        let nextChar = 65; // 'A'
                        let pattern = '';
                        for (const char of label) {{
                            if (char >= 'a' && char <= 'z') {{
                                if (!map.has(char)) {{
                                    map.set(char, String.fromCharCode(nextChar++));
                                }}
                                pattern += map.get(char);
                            }}
                        }}

                        return {{
                            ...r,
                            _label: label,
                            _queryTarget: domainLower,
                            _isVowelOnly: isVowelOnly,
                            _isConsonantOnly: isConsonantOnly,
                            _hasVowel: hasVowel,
                            _isAlternating: isAlternating,
                            _pattern: pattern
                        }};
                    }})
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
