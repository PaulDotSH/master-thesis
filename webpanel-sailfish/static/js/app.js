(function () {
  var modal = document.getElementById('modal-overlay');
  var modalTitle = document.getElementById('modal-title');
  var modalBody = document.getElementById('modal-body');
  var detailPrefix = 'scan detail #';

  document.addEventListener('click', function (e) {
    var link = e.target.closest('.scan-detail-link');
    if (!link) return;
    e.preventDefault();
    var id = link.getAttribute('data-id');
    openModal(id);
  });

  if (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target === modal) closeModal();
    });
  }

  // Modal: close on Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeModal();
  });

  window.openModal = function (id) {
    if (!modal || !modalBody) return;
    modal.style.display = 'flex';
    modalTitle.textContent = detailPrefix + id;
    modalBody.innerHTML = '<div class="spinner"></div>';
    showLoading(id);
  };

  window.closeModal = function () {
    if (modal) modal.style.display = 'none';
  };

  function showLoading(id) {
    fetch('/api/scan-results/' + id)
      .then(function (r) { return r.json(); })
      .then(renderDetail)
      .catch(function () { modalBody.innerHTML = '<p style="color:var(--red)">Failed to load details.</p>'; });
  }

  function renderDetail(d) {
    if (!d) { modalBody.innerHTML = '<p>No data.</p>'; return; }
    modalTitle.textContent = 'Scan Detail — ' + d.crate_name + ' (#' + d.id + ')';
    var fields = [
      ['Crate', '<a href="https://crates.io/crates/' + d.crate_name + '" target="_blank">' + esc(d.crate_name) + '</a>'],
      ['LLM Score', '<span class="badge badge-' + riskClass(d.llm_malicious_score) + '">' + d.llm_malicious_score + ' / 100</span>'],
      ['LLM Notes', esc(d.llm_notes || '—')],
      ['Malicious Dependencies', boolBadge(d.has_malicious_dependencies)],
      ['Executable Files', boolBadge(d.has_executable_files)],
      ['Cargo Audit Max Score', d.cargo_audit_max_dep_score],
      ['Cargo Audit Vulns Count', d.cargo_audit_vulns_count],
      ['Build.rs Network Calls', boolBadge(d.build_rs_network_calls)],
      ['Build.rs Link Directive', boolBadge(d.build_rs_has_link_directive)],
      ['Build.rs Process Spawning', boolBadge(d.build_rs_has_process_spawning)],
      ['Build.rs Raw IP', boolBadge(d.build_rs_has_raw_ip)],
      ['Build.rs Free TLDs', boolBadge(d.build_rs_has_free_tlds)],
      ['Build.rs Entropy Score', d.build_rs_entropy_score.toFixed(2)]
    ];
    var h = '';
    for (var i = 0; i < fields.length; i++) {
      h += '<div class="kv"><span class="kv-label">' + fields[i][0] + '</span><span class="kv-value">' + fields[i][1] + '</span></div>';
    }
    modalBody.innerHTML = h;
  }

  function riskClass(s) {
    if (s <= 30) return 'low';
    if (s <= 60) return 'medium';
    if (s <= 80) return 'high';
    return 'critical';
  }

  function boolBadge(b) {
    return b
      ? '<span class="badge badge-yes">Yes</span>'
      : '<span class="badge badge-no">No</span>';
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
})();
