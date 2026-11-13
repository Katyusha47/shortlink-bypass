/**
 * Universal Shortlink Bypasser - Client Application
 * Lightweight vanilla JavaScript with zero external runtime dependencies.
 */

(function () {
  'use strict';

  // 1. Theme Switcher (Light / Dark)
  const THEME_KEY = 'usb_theme_preference';

  function initTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const activeTheme = savedTheme || (prefersDark ? 'dark' : 'light');

    document.documentElement.setAttribute('data-theme', activeTheme);
    updateThemeIcon(activeTheme);

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem(THEME_KEY, newTheme);
        updateThemeIcon(newTheme);
      });
    }
  }

  function updateThemeIcon(theme) {
    const toggleBtn = document.getElementById('theme-toggle');
    if (!toggleBtn) return;
    const isDark = theme === 'dark';
    toggleBtn.innerHTML = isDark
      ? '<svg class="theme-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>'
      : '<svg class="theme-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>';
    toggleBtn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  // 2. URL Resolution Controller
  function initResolver() {
    const form = document.getElementById('resolve-form');
    const input = document.getElementById('url-input');
    const submitBtn = document.getElementById('submit-btn');
    const resultContainer = document.getElementById('result-container');

    if (!form || !input || !submitBtn || !resultContainer) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const rawUrl = input.value.trim();

      if (!rawUrl) {
        showError('Please enter a shortened URL to resolve.');
        input.focus();
        return;
      }

      setLoadingState(true);
      clearResults();

      try {
        const response = await fetch('/api/resolve', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({ url: rawUrl }),
        });

        const data = await response.json();

        if (response.status === 429) {
          const retryAfter = data.detail?.retry_after || 30;
          showError(`Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`);
          return;
        }

        if (!response.ok && !data.original_url) {
          showError(data.error || data.detail || 'Failed to process resolution request.');
          return;
        }

        renderResult(data);
      } catch (err) {
        showError('Network communication error. Please check your internet connection and try again.');
      } finally {
        setLoadingState(false);
      }
    });

    function setLoadingState(loading) {
      if (loading) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Resolving Link...';
      } else {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Resolve Link';
      }
    }

    function clearResults() {
      resultContainer.innerHTML = '';
    }

    function showError(message) {
      resultContainer.innerHTML = `
        <div class="result-card error" role="alert">
          <div class="result-header">
            <span class="status-badge blocked">Error</span>
          </div>
          <p style="color: var(--text-primary); font-size: 0.95rem;">${escapeHtml(message)}</p>
        </div>
      `;
    }

    function renderResult(data) {
      const isSuccess = data.success && data.destination_url;
      const statusClass = (data.status || 'unknown').toLowerCase();
      const categoryClass = (data.category || 'generic_redirect').toLowerCase();

      let metadataHtml = '';
      if (data.metadata) {
        if (data.metadata.filename) {
          metadataHtml += `<div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.25rem;"><strong>File:</strong> ${escapeHtml(data.metadata.filename)}</div>`;
        }
        if (data.metadata.file_size_formatted) {
          metadataHtml += `<div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.25rem;"><strong>Size:</strong> ${escapeHtml(data.metadata.file_size_formatted)}</div>`;
        }
        if (data.metadata.is_direct_download) {
          metadataHtml += `<div style="display: inline-block; font-size: 0.75rem; background: var(--success-bg); color: var(--success); padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; margin-top: 0.25rem;">Direct Download Link</div>`;
        }
      }

      let traceHtml = '';
      if (data.trace && data.trace.length > 0) {
        const traceItems = data.trace.map((hop, index) => {
          return `
            <li class="trace-item">
              <span class="trace-hop-num">#${index + 1}</span>
              <span class="trace-status">${hop.status_code || 200}</span>
              <span>${escapeHtml(hop.url)}</span>
            </li>
          `;
        }).join('');

        traceHtml = `
          <details class="trace-details">
            <summary>View Redirect Chain (${data.trace.length} hop${data.trace.length > 1 ? 's' : ''})</summary>
            <ul class="trace-list">
              ${traceItems}
            </ul>
          </details>
        `;
      }

      if (isSuccess) {
        resultContainer.innerHTML = `
          <div class="result-card success" role="region" aria-label="Resolution Result">
            <div class="result-header">
              <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                <span class="provider-badge ${categoryClass}">${escapeHtml(data.provider)}</span>
                <span class="status-badge ${statusClass}">Resolved</span>
                ${data.redirect_count > 0 ? `<span style="font-size: 0.775rem; color: var(--text-muted); font-weight: 500;">${data.redirect_count} redirect${data.redirect_count > 1 ? 's' : ''} followed</span>` : ''}
              </div>
            </div>

            <div class="destination-box" id="destination-output">${escapeHtml(data.destination_url)}</div>

            ${metadataHtml}

            <div class="result-actions">
              <button type="button" class="btn btn-secondary" id="copy-btn">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                <span id="copy-text">Copy URL</span>
              </button>
              <a href="${escapeHtml(data.destination_url)}" target="_blank" rel="noopener noreferrer" class="btn btn-outline">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                Open Destination
              </a>
            </div>

            ${traceHtml}
          </div>
        `;

        // Wire up copy button
        const copyBtn = document.getElementById('copy-btn');
        const copyText = document.getElementById('copy-text');
        if (copyBtn && copyText) {
          copyBtn.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(data.destination_url);
              copyText.textContent = 'Copied!';
              copyBtn.style.borderColor = 'var(--success)';
              setTimeout(() => {
                copyText.textContent = 'Copy URL';
                copyBtn.style.borderColor = '';
              }, 2000);
            } catch (err) {
              copyText.textContent = 'Failed to copy';
            }
          });
        }
      } else {
        // Unsuccessful resolution (blocked, expired, inaccessible, etc.)
        resultContainer.innerHTML = `
          <div class="result-card error" role="region" aria-label="Resolution Notice">
            <div class="result-header">
              <span class="provider-badge ${categoryClass}">${escapeHtml(data.provider || 'Provider')}</span>
              <span class="status-badge ${statusClass}">${escapeHtml(data.status)}</span>
            </div>
            <p style="color: var(--text-primary); font-size: 0.95rem; margin-bottom: 0.5rem;">
              <strong>Resolution Status:</strong> ${escapeHtml(data.error || 'Destination could not be retrieved.')}
            </p>
            ${traceHtml}
          </div>
        `;
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  }

  // Initialize on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initTheme();
      initResolver();
    });
  } else {
    initTheme();
    initResolver();
  }
})();

