/**
 * Frontend controller admin WP Root Guard.
 *
 * Menangani:
 * 1. Trigger scan via AJAX dengan progress bar / animasi antrean scan.
 * 2. Modal inspeksi berkas (Secure Code Inspector).
 * 3. Modal perbandingan kode (Diff Viewer).
 * 4. Sticky floating bulk action bar.
 * 5. Pengaturan notifikasi dan aksi form administratif.
 *
 * @package WPRootGuard
 * @since   3.2.0
 */
(function ($) {
	'use strict';

	// Pastikan objek konfigurasi wpRootGuard tersedia
	window.wpRootGuard = window.wpRootGuard || {
		ajaxUrl: typeof ajaxurl !== 'undefined' ? ajaxurl : '/wp-admin/admin-ajax.php',
		nonce: '',
		i18n: {}
	};

	var WPRootGuard = {
		/**
		 * Inisialisasi semua komponen admin Root Guard.
		 */
		init: function () {
			this.bindScanButton();
			this.bindInspectButtons();
			this.bindBulkActions();
			this.bindStickyBar();
			this.bindSettingsToggles();
			this.bindModalKeyboard();

			// Auto resume scan if active scan is running in background (e.g. after refresh)
			if ($('#rg-status-card').hasClass('rg-status-scanning')) {
				WPRootGuard.runScan();
			}
		},

		/**
		 * Mengikat tombol trigger pemindaian.
		 */
		bindScanButton: function () {
			$(document).on('click', '#rg-scan-now', function (e) {
				e.preventDefault();
				WPRootGuard.runScan();
			});
		},

		/**
		 * Menjalankan pemindaian via AJAX dengan animasi antrean atau progress bar.
		 */
		runScan: function () {
			var $btn = $('#rg-scan-now');
			var $progress = $('#rg-scan-progress');
			var scanningText = (wpRootGuard.i18n && wpRootGuard.i18n.scanning) ? wpRootGuard.i18n.scanning : 'Memindai...';
			var errorText = (wpRootGuard.i18n && wpRootGuard.i18n.error) ? wpRootGuard.i18n.error : 'Terjadi kesalahan pada server.';

			$btn.prop('disabled', true).text(scanningText);

			var inlineCard = document.getElementById('rg-scan-inline-card');
			var statusCard = document.getElementById('rg-status-card');
			var summaryCard = document.getElementById('rg-summary-card');
			var actionsBar = document.getElementById('rg-actions-bar');
			var heroCard = document.getElementById('rg-clean-hero-card');
			var tableCards = document.querySelectorAll('.rg-table-card');
			var percentText = document.getElementById('rg-scan-percentage');
			var progressBar = document.getElementById('rg-scan-bar');
			var currentItemText = document.getElementById('rg-scan-current-item');
			var counterText = document.getElementById('rg-scan-counter');
			var shieldIcon = document.getElementById('rg-shield-icon');

			function updateStageUI(stageNum) {
				for (var s = 1; s <= 5; s++) {
					var stageEl = document.getElementById('rg-stage-' + s);
					if (!stageEl) continue;
					if (s < stageNum) {
						stageEl.className = 'rg-stage-pill completed';
					} else if (s === stageNum) {
						stageEl.className = 'rg-stage-pill active';
					} else {
						stageEl.className = 'rg-stage-pill';
					}
				}
			}

			function safeHtml(str) {
				return $('<div>').text(str || '').html();
			}

			function numberFormat(num) {
				return (num || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
			}

			function renderTicker(folder, file, scope) {
				if (!currentItemText) return;
				var badge = '📄 [Berkas]';
				if (scope === 'root_folders') {
					badge = '📂 [Folder Root]';
				} else if (scope === 'root_files') {
					badge = '📄 [Berkas Root]';
				} else if (scope === 'core_checksums' || scope === 'core_injected_files') {
					badge = '🛡️ [Core Checksum]';
				} else if (scope === 'uploads_php') {
					badge = '🚨 [Uploads / Malware]';
				} else if (scope === 'database_integrity') {
					badge = '🗄️ [Database Guard]';
				}
				currentItemText.innerHTML = '<span class="rg-ticker-badge">' + badge + '</span> ' +
					'<span style="color: #94a3b8;">' + safeHtml(folder) + '</span> ' +
					'<strong style="color: #f1f5f9; margin-left: 4px;">' + safeHtml(file) + '</strong>';
			}

			// Jika kartu scanner interaktif tersedia di halaman
			if (inlineCard) {
				if (statusCard) statusCard.style.display = 'none';
				if (summaryCard) summaryCard.style.display = 'none';
				if (actionsBar) actionsBar.style.display = 'none';
				if (heroCard) heroCard.style.display = 'none';
				if (tableCards) {
					tableCards.forEach(function (card) { card.style.display = 'none'; });
				}

				inlineCard.classList.remove('hidden');
				inlineCard.style.display = 'block';

				if (percentText) {
					percentText.innerText = '0%';
					percentText.style.color = '#38bdf8';
				}
				if (progressBar) {
					progressBar.style.width = '0%';
					progressBar.style.background = 'linear-gradient(90deg, #3b82f6 0%, #06b6d4 50%, #10b981 100%)';
				}
				if (counterText) counterText.innerText = '0 / 0 Berkas & Tabel';
				if (shieldIcon) {
					shieldIcon.innerText = '🛡️';
					shieldIcon.style.filter = 'drop-shadow(0 0 12px rgba(56, 189, 248, 0.5))';
				}
				if (currentItemText) {
					var wpInfo = (window.wpRootGuard && window.wpRootGuard.wpVersion) ? ' (WordPress v' + window.wpRootGuard.wpVersion + ')' : '';
					currentItemText.innerHTML = '⚡ <span style="color: #38bdf8;">[INIT] Menghubungkan ke pemindai sistem' + wpInfo + ' & menyesuaikan checksums resmi...</span>';
				}
				updateStageUI(1);

				// Smooth scroll to inlineCard
				try {
					var targetTop = $(inlineCard).offset().top - 40;
					$('html, body').animate({ scrollTop: targetTop }, 300);
				} catch (e) {}

				var isScanningRunning = true;

				function executeBackendBatch() {
					if (!isScanningRunning) return;

					$.post(wpRootGuard.ajaxUrl, {
						action: 'wp_root_guard_run_scan',
						nonce: wpRootGuard.nonce,
						security: wpRootGuard.nonce
					}, function (scanResponse) {
						if (scanResponse && scanResponse.success) {
							var res = (scanResponse.data && scanResponse.data.results) ? scanResponse.data.results : {};
							var progress = res.progress || {};
							var executionState = res.execution_state || '';
							var isCompleted = (executionState === 'completed');

							// Map scope to 5 stages
							var scope = progress.scope || 'root_folders';
							var stageNum = 1;
							if (scope === 'root_folders') stageNum = 1;
							else if (scope === 'root_files') stageNum = 2;
							else if (scope === 'core_checksums' || scope === 'core_injected_files') stageNum = 3;
							else if (scope === 'uploads_php') stageNum = 4;
							else if (scope === 'database_integrity' || scope === 'remediate') stageNum = 5;
							else if (isCompleted) stageNum = 5;

							updateStageUI(stageNum);

							var processed = parseInt(progress.processed || 0, 10);
							var total = parseInt(progress.total || 0, 10);
							var folder = progress.current_folder || 'Root';
							var file = progress.current_file || '';
							var recent = progress.recent_items || [];

							// Dynamic percentage
							var pct = 0;
							if (isCompleted) {
								pct = 100;
							} else if (total > 0) {
								pct = Math.min(98, Math.max(2, Math.floor((processed / total) * 98)));
							} else {
								pct = 5;
							}

							if (percentText) percentText.innerText = pct + '%';
							if (progressBar) progressBar.style.width = pct + '%';

							if (counterText) {
								var dispTotal = Math.max(total, processed);
								counterText.innerText = numberFormat(processed) + ' / ' + numberFormat(dispTotal) + ' Berkas & Tabel';
							}

							if (file) {
								renderTicker(folder, file, scope);
							}

							if (!isCompleted) {
								// Sub-ticker rapid animation through recent items
								if (recent && recent.length > 1) {
									var itemIdx = 0;
									var miniTimer = setInterval(function () {
										itemIdx++;
										if (itemIdx < recent.length) {
											var itm = recent[itemIdx];
											renderTicker(itm.folder, itm.file, itm.scope);
										} else {
											clearInterval(miniTimer);
										}
									}, 35);
								}
								// Schedule next batch
								setTimeout(executeBackendBatch, 60);
								return;
							}

							// Completed celebration!
							isScanningRunning = false;
							for (var s = 1; s <= 5; s++) {
								var stageEl = document.getElementById('rg-stage-' + s);
								if (stageEl) stageEl.className = 'rg-stage-pill completed';
							}
							if (percentText) {
								percentText.innerText = '100%';
								percentText.style.color = '#34d399';
							}
							if (progressBar) {
								progressBar.style.width = '100%';
								progressBar.style.background = 'linear-gradient(90deg, #10b981 0%, #34d399 100%)';
							}
							if (shieldIcon) {
								shieldIcon.innerText = '✅';
								shieldIcon.style.filter = 'drop-shadow(0 0 16px rgba(52, 211, 153, 0.8))';
							}
							if (currentItemText) {
								currentItemText.innerHTML = '<strong style="color: #34d399;">✅ Pemindaian Selesai! Semua direktori dan database WordPress terverifikasi. Memuat dashboard...</strong>';
							}

							setTimeout(function () {
								window.location.href = '?page=wp-root-guard&tab=dashboard&message=scanned';
							}, 900);

						} else {
							var msg = (scanResponse && scanResponse.data && scanResponse.data.message) ? scanResponse.data.message : errorText;
							if (currentItemText) {
								currentItemText.innerHTML = '<span style="color: #f87171;">⚠️ ' + safeHtml(msg) + '</span>';
							}
							alert(msg);
							$btn.prop('disabled', false).text('Pindai Sekarang (Scan Now)');
						}
					}).fail(function () {
						WPRootGuard.submitRgAction('scan_now');
					});
				}

				// Execute first batch immediately
				executeBackendBatch();
			} else {
				// Fallback mode jika tidak ada elemen kartu inline
				if ($progress.length) {
					$progress.show().find('.rg-progress-fill').css('width', '0%');
				}

				$.post(wpRootGuard.ajaxUrl, {
					action: 'wp_root_guard_run_scan',
					nonce: wpRootGuard.nonce,
					security: wpRootGuard.nonce
				})
					.done(function (response) {
						if (response.success) {
							if (response.data && response.data.results && response.data.results.execution_state !== 'completed') {
								setTimeout(function () { WPRootGuard.runScan(); }, 250);
								return;
							}
							if ($progress.length) {
								$progress.find('.rg-progress-fill').css('width', '100%');
							}
							setTimeout(function () {
								window.location.reload();
							}, 500);
						} else {
							alert((response.data && response.data.message) ? response.data.message : errorText);
							$btn.prop('disabled', false).text('Pindai Sekarang (Scan Now)');
						}
					})
					.fail(function () {
						alert(errorText);
						$btn.prop('disabled', false).text('Pindai Sekarang (Scan Now)');
					});
			}
		},

		/**
		 * Mengikat tombol inspeksi kode berkas.
		 */
		bindInspectButtons: function () {
			$(document).on('click', '.rg-inspect', function (e) {
				e.preventDefault();
				var path = $(this).data('path') || $(this).attr('data-file');
				if (path) {
					WPRootGuard.inspectFile(path);
				}
			});
		},

		/**
		 * Mengirim permintaan AJAX untuk inspeksi konten berkas secara aman.
		 *
		 * @param {string} path Path relatif berkas.
		 */
		inspectFile: function (path) {
			var modal = document.getElementById('rg-code-modal') || document.getElementById('rg-inspector-modal');
			var filenameEl = document.getElementById('rg-modal-filename');
			var statsEl = document.getElementById('rg-modal-stats');
			var loadingEl = document.getElementById('rg-modal-loading');
			var loadingPct = document.getElementById('rg-modal-loading-pct');
			var loadingBar = document.getElementById('rg-modal-loading-bar');
			var errorEl = document.getElementById('rg-modal-error');
			var codeTable = document.getElementById('rg-modal-codetable');
			var codeBody = document.getElementById('rg-modal-codebody');
			var actionsEl = document.getElementById('rg-modal-actions');
			var errorText = (wpRootGuard.i18n && wpRootGuard.i18n.error) ? wpRootGuard.i18n.error : 'Terjadi kesalahan saat membaca berkas.';

			if (filenameEl) filenameEl.innerText = path;
			if (statsEl) statsEl.innerText = (wpRootGuard.i18n && wpRootGuard.i18n.loading_analysis) ? wpRootGuard.i18n.loading_analysis : 'Memuat analisis...';
			if (loadingPct) loadingPct.innerText = '25%';
			if (loadingBar) loadingBar.style.width = '25%';
			if (loadingEl) loadingEl.style.display = 'block';
			if (errorEl) errorEl.style.display = 'none';
			if (codeTable) codeTable.style.display = 'none';
			if (codeBody) codeBody.innerHTML = '';
			if (actionsEl) actionsEl.innerHTML = '';
			if (modal) modal.style.display = 'flex';

			$.post(wpRootGuard.ajaxUrl, {
				action: 'wp_root_guard_inspect_file',
				nonce: wpRootGuard.nonce,
				security: wpRootGuard.nonce,
				path: path,
				file: path
			})
				.done(function (response) {
					if (loadingPct) loadingPct.innerText = '90%';
					if (loadingBar) loadingBar.style.width = '90%';

					setTimeout(function () {
						if (loadingEl) loadingEl.style.display = 'none';

						if (response.success && response.data) {
							WPRootGuard.showInspector(response.data, path);
						} else {
							var msg = (response.data && response.data.message) ? response.data.message : errorText;
							if (errorEl) {
								errorEl.innerText = '❌ ' + msg;
								errorEl.style.display = 'block';
							} else {
								alert(msg);
							}
						}
					}, 150);
				})
				.fail(function () {
					if (loadingEl) loadingEl.style.display = 'none';
					if (errorEl) {
						errorEl.innerText = '❌ ' + errorText;
						errorEl.style.display = 'block';
					} else {
						alert(errorText);
					}
				});
		},

		/**
		 * Menampilkan kode berkas di dalam modal inspeksi.
		 *
		 * @param {object} data Objek respon data hasil inspeksi berkas.
		 * @param {string} path Path berkas opsional.
		 */
		showInspector: function (data, path) {
			var $inspectorModal = $('#rg-inspector-modal');
			var $codeModal = $('#rg-code-modal');

			var fileName = path || data.file || 'berkas';
			var safeFileName = fileName.replace(/'/g, "\\'");

			// Dukungan untuk struktur tampilan modal kode bawaan (#rg-code-modal)
			if ($codeModal.length) {
				var statsEl = document.getElementById('rg-modal-stats');
				var codeTable = document.getElementById('rg-modal-codetable');
				var codeBody = document.getElementById('rg-modal-codebody');
				var actionsEl = document.getElementById('rg-modal-actions');

				var totalLines = data.total_lines || (data.lines ? data.lines.length : 0);
				var totalDangers = data.total_dangers || 0;

				var statsText = 'Total Baris: ' + totalLines;
				if (totalDangers > 0) {
					statsText += ' | ⚠️ TERDETEKSI ' + totalDangers + ' INDIKASI BAHAYA MALWARE';
				} else {
					statsText += ' | ✅ Tidak terdeteksi tanda tangan malware berbahaya';
				}
				if (statsEl) statsEl.innerText = statsText;

				var rowsHtml = '';
				if (data.lines && data.lines.length) {
					data.lines.forEach(function (item) {
						var isDanger = item.dangers && item.dangers.length > 0;
						var trStyle = isDanger ? 'background: #450a0a; color: #fecaca; font-weight: 600;' : 'color: #e2e8f0;';
						var lineStyle = isDanger ? 'background: #7f1d1d; color: #fca5a5;' : 'background: #1e293b; color: #64748b;';

						rowsHtml += '<tr style="' + trStyle + '">';
						rowsHtml += '<td style="width: 50px; text-align: right; padding: 2px 10px; user-select: none; border-right: 1px solid #334155; ' + lineStyle + '">' + item.line_number + '</td>';
						rowsHtml += '<td style="padding: 2px 12px; white-space: pre-wrap; word-break: break-all;">';

						if (isDanger) {
							rowsHtml += '<span style="background: #dc2626; color: #ffffff; padding: 1px 6px; border-radius: 4px; font-size: 11px; margin-right: 8px; font-weight: bold;">⚠️ BAHAYA: ' + item.dangers.join(', ') + '</span>';
						}

						rowsHtml += WPRootGuard.escapeHtml(item.code);
						rowsHtml += '</td>';
						rowsHtml += '</tr>';
					});
				}

				if (codeBody) codeBody.innerHTML = rowsHtml;
				if (codeTable) codeTable.style.display = 'table';

				if (actionsEl) {
					var actionsHtml = '';
					actionsHtml += '<button type="button" class="button button-secondary" onclick="trustFolder(\'' + safeFileName + '\')">👍 Trust File</button> ';
					actionsHtml += '<button type="button" class="button button-secondary" onclick="if(confirm(\'Karantina berkas ini?\')) { submitFolderAction(\'quarantine_file\', \'' + safeFileName + '\'); }">🔒 Karantina</button> ';
					actionsHtml += '<button type="button" class="button button-link-delete" style="color: #dc2626; border-color: #fca5a5;" onclick="if(confirm(\'Apakah Anda yakin ingin menghapus berkas ini secara PERMANEN?\')) { submitFolderAction(\'delete_file_directly\', \'' + safeFileName + '\'); }">🗑️ Hapus Permanen</button>';
					actionsEl.innerHTML = actionsHtml;
				}

				$codeModal.css('display', 'flex');
			}

			// Dukungan untuk struktur modal rg-inspector-modal
			if ($inspectorModal.length) {
				var $content = $inspectorModal.find('.rg-inspector-content');
				$content.empty();
				if (data.lines && data.lines.length) {
					data.lines.forEach(function (line) {
						var classes = 'rg-line';
						if (line.dangers && line.dangers.length) {
							classes += ' rg-danger';
						}
						var html = '<div class="' + classes + '">';
						html += '<span class="rg-line-num">' + line.line_number + '</span>';
						html += '<code>' + WPRootGuard.escapeHtml(line.code) + '</code>';
						html += '</div>';
						$content.append(html);
					});
				}
				$inspectorModal.show();
			}
		},

		/**
		 * Helper untuk sanitasi/escaping string HTML.
		 *
		 * @param {string} str String yang akan diescape.
		 * @return {string} String hasil escape.
		 */
		escapeHtml: function (str) {
			if (!str) return '';
			return $('<div/>').text(str).html();
		},

		/**
		 * Mengikat aksi checkbox tabel dan bar aksi massal (Bulk Actions).
		 */
		bindBulkActions: function () {
			$(document).on('change', '.rg-select-all', function () {
				var checked = $(this).prop('checked');
				$(this).closest('table').find('.rg-checkbox, .rg-item-checkbox').prop('checked', checked);
				WPRootGuard.updateBulkBar();
			});

			$(document).on('change', '.rg-checkbox, .rg-item-checkbox', function () {
				WPRootGuard.updateBulkBar();
			});
		},

		/**
		 * Memperbarui counter jumlah item terpilih dan status visual floating bulk bar.
		 */
		updateBulkBar: function () {
			var count = $('.rg-checkbox:checked, .rg-item-checkbox:checked').length;
			var $bar = $('.rg-bulk-bar');
			var $counter = $('#rg-selected-count');

			if ($counter.length) {
				$counter.text(count);
			}

			if ($bar.length) {
				$bar.find('.rg-bulk-count').text(count);
				if (count > 0) {
					$bar.addClass('rg-active');
				} else {
					$bar.removeClass('rg-active');
				}
			}
		},

		/**
		 * Mengikat efek sticky pada floating bulk action bar saat menggulir halaman.
		 */
		bindStickyBar: function () {
			var $bar = $('.rg-bulk-bar');
			if (!$bar.length) {
				return;
			}

			$(window).on('scroll', function () {
				if ($(window).scrollTop() > 100) {
					$bar.addClass('rg-sticky');
				} else {
					$bar.removeClass('rg-sticky');
				}
			});
		},

		/**
		 * Mengikat tombol switch konfigurasi pada tab Settings.
		 */
		bindSettingsToggles: function () {
			var emailToggle = document.getElementById('rg-toggle-email');
			if (emailToggle) {
				emailToggle.addEventListener('change', function () {
					var section = document.getElementById('rg-email-fields');
					if (section) {
						if (this.checked) {
							section.classList.remove('hidden');
							section.style.display = '';
						} else {
							section.classList.add('hidden');
							section.style.display = 'none';
						}
					}
				});
			}

			var tgToggle = document.getElementById('rg-toggle-telegram');
			if (tgToggle) {
				tgToggle.addEventListener('change', function () {
					var section = document.getElementById('rg-telegram-fields');
					if (section) {
						if (this.checked) {
							section.classList.remove('hidden');
							section.style.display = '';
						} else {
							section.classList.add('hidden');
							section.style.display = 'none';
						}
					}
				});
			}
		},

		/**
		 * Mengikat tombol Escape keyboard untuk menutup modal.
		 */
		bindModalKeyboard: function () {
			document.addEventListener('keydown', function (e) {
				if (e.key === 'Escape') {
					WPRootGuard.closeCodeInspector();
				}
			});
		},

		/**
		 * Menutup modal inspektur kode.
		 */
		closeCodeInspector: function () {
			var modal = document.getElementById('rg-code-modal');
			if (modal) modal.style.display = 'none';
			var inspectModal = document.getElementById('rg-inspector-modal');
			if (inspectModal) inspectModal.style.display = 'none';
		},

		/**
		 * Mengirim form aksi global rg-action-form.
		 *
		 * @param {string} action Nama aksi.
		 */
		submitRgAction: function (action) {
			var form = document.getElementById('rg-action-form');
			var field = document.getElementById('rg-action-field');
			if (field && form) {
				field.value = action;
				form.submit();
			}
		},

		/**
		 * Mengirim aksi spesifik pada folder/berkas ke rg-action-form.
		 *
		 * @param {string} action Nama aksi.
		 * @param {string} folderName Nama folder atau berkas target.
		 */
		submitFolderAction: function (action, folderName) {
			var form = document.getElementById('rg-action-form');
			var actionField = document.getElementById('rg-action-field');
			var folderField = document.getElementById('rg-folder-field');
			if (form && actionField && folderField) {
				actionField.value = action;
				folderField.value = folderName;
				form.submit();
			}
		}
	};

	// Daftarkan fungsi pembantu ke window global untuk kompatibilitas onclick bawaan
	window.WPRootGuard = WPRootGuard;
	window.openCodeInspector = function (fileName) {
		WPRootGuard.inspectFile(fileName);
	};
	window.closeCodeInspector = function () {
		WPRootGuard.closeCodeInspector();
	};
	window.toggleSelectAllTable = function (masterCheckbox) {
		var table = masterCheckbox.closest('table');
		if (table) {
			var checkboxes = table.querySelectorAll('.rg-item-checkbox, .rg-checkbox');
			checkboxes.forEach(function (cb) {
				cb.checked = masterCheckbox.checked;
			});
			WPRootGuard.updateBulkBar();
		}
	};
	window.updateSelectedCount = function () {
		WPRootGuard.updateBulkBar();
	};
	window.executeBulkAction = function () {
		var actionSelect = document.getElementById('rg_bulk_action_type');
		var action = actionSelect ? actionSelect.value : '';
		var checkedCount = document.querySelectorAll('.rg-item-checkbox:checked, .rg-checkbox:checked').length;

		if (!action) {
			alert((wpRootGuard.i18n && wpRootGuard.i18n.select_bulk_action) ? wpRootGuard.i18n.select_bulk_action : 'Silakan pilih jenis tindakan massal terlebih dahulu.');
			return;
		}

		if (checkedCount === 0) {
			alert((wpRootGuard.i18n && wpRootGuard.i18n.select_bulk_items) ? wpRootGuard.i18n.select_bulk_items : 'Silakan centang/pilih minimal 1 item ancaman dari tabel.');
			return;
		}

		var message = '';
		if (action === 'bulk_fix_core') {
			message = 'Apakah Anda yakin ingin MEMPERBAIKI ' + checkedCount + ' berkas core yang dipilih dengan mengunduh berkas asli resmi langsung dari SVN WordPress.org?';
		} else if (action === 'bulk_trust') {
			message = 'Apakah Anda yakin ingin menambahkan ' + checkedCount + ' item ancaman yang dipilih ke Whitelist Kustom?';
		} else if (action === 'bulk_quarantine') {
			message = 'Apakah Anda yakin ingin memindahkan ' + checkedCount + ' item ancaman yang dipilih ke Karantina?';
		} else if (action === 'bulk_delete') {
			message = 'PERINGATAN BAHAYA: Apakah Anda yakin ingin menghapus ' + checkedCount + ' berkas/folder ancaman yang dipilih secara PERMANEN dari server? Aksi ini tidak dapat dibatalkan!';
		}

		if (confirm(message)) {
			var form = document.getElementById('rg-bulk-form');
			if (form) form.submit();
		}
	};
	window.startDynamicScan = function () {
		WPRootGuard.runScan();
	};
	window.submitRgAction = function (action) {
		WPRootGuard.submitRgAction(action);
	};
	window.trustFolder = function (folderName) {
		WPRootGuard.submitFolderAction('trust_folder', folderName);
	};
	window.untrustFolder = function (folderName) {
		WPRootGuard.submitFolderAction('untrust_folder', folderName);
	};
	window.submitFolderAction = function (action, folderName) {
		WPRootGuard.submitFolderAction(action, folderName);
	};
	window.toggleAllLogs = function (btn) {
		var hidden = document.getElementById('rg-log-body-hidden');
		var container = document.getElementById('rg-log-container');
		if (!hidden || !container) return;
		if (hidden.style.display === 'none') {
			hidden.style.display = '';
			container.style.maxHeight = '600px';
			btn.innerHTML = '🔼 ' + ((wpRootGuard.i18n && wpRootGuard.i18n.hide_old_logs) ? wpRootGuard.i18n.hide_old_logs : 'Sembunyikan Log Lama');
		} else {
			hidden.style.display = 'none';
			container.style.maxHeight = '340px';
			btn.innerHTML = '🔽 ' + ((wpRootGuard.i18n && wpRootGuard.i18n.show_more_logs) ? wpRootGuard.i18n.show_more_logs : 'Tampilkan Log Lainnya');
		}
	};
	window.toggleCleanDetails = function (btn) {
		var panel = document.getElementById('rg-clean-details-panel');
		if (!panel) return;
		if (panel.style.display === 'none' || panel.style.display === '') {
			panel.style.display = 'block';
			if (btn) btn.innerHTML = '🔼 Sembunyikan Rincian Komponen';
		} else {
			panel.style.display = 'none';
			if (btn) btn.innerHTML = '📋 Lihat Rincian Komponen Terverifikasi';
		}
	};
	window.triggerTestNotification = function (action) {
		var mainForm = document.getElementById('rg-action-form');
		var actionField = document.getElementById('rg-action-field');
		if (!mainForm || !actionField) return;

		var oldToken = document.getElementById('rg-test-token');
		if (oldToken) oldToken.remove();
		var oldChat = document.getElementById('rg-test-chat');
		if (oldChat) oldChat.remove();
		var oldEmail = document.getElementById('rg-test-email');
		if (oldEmail) oldEmail.remove();

		if (action === 'test_telegram') {
			var tokenField = document.getElementById('telegram_bot_token');
			var chatField = document.getElementById('telegram_chat_id');
			var tokenVal = tokenField ? tokenField.value : '';
			var chatVal = chatField ? chatField.value : '';

			if (!tokenVal || !chatVal) {
				alert((wpRootGuard.i18n && wpRootGuard.i18n.fill_telegram_fields) ? wpRootGuard.i18n.fill_telegram_fields : 'Mohon isi Bot Token dan Chat ID terlebih dahulu untuk uji coba!');
				return;
			}

			var tokenInput = document.createElement('input');
			tokenInput.type = 'hidden';
			tokenInput.name = 'telegram_bot_token';
			tokenInput.id = 'rg-test-token';
			tokenInput.value = tokenVal;
			mainForm.appendChild(tokenInput);

			var chatInput = document.createElement('input');
			chatInput.type = 'hidden';
			chatInput.name = 'telegram_chat_id';
			chatInput.id = 'rg-test-chat';
			chatInput.value = chatVal;
			mainForm.appendChild(chatInput);

		} else if (action === 'test_email') {
			var emailField = document.getElementById('admin_email');
			var emailVal = emailField ? emailField.value : '';

			if (!emailVal) {
				alert((wpRootGuard.i18n && wpRootGuard.i18n.fill_email_field) ? wpRootGuard.i18n.fill_email_field : 'Mohon isi alamat email terlebih dahulu untuk uji coba!');
				return;
			}

			var emailInput = document.createElement('input');
			emailInput.type = 'hidden';
			emailInput.name = 'admin_email';
			emailInput.id = 'rg-test-email';
			emailInput.value = emailVal;
			mainForm.appendChild(emailInput);
		}

		actionField.value = action;
		mainForm.submit();
	};

	window.startDynamicScan = function () {
		WPRootGuard.runScan();
	};

	window.submitDbAction = function (action, target) {
		var form = document.getElementById('rg-action-form');
		var actField = document.getElementById('rg-action-field');
		var folderField = document.getElementById('rg-folder-field');
		if (form && actField && folderField) {
			actField.value = action;
			folderField.value = target;
			form.submit();
		}
	};

	$(document).ready(function () {
		WPRootGuard.init();
	});
})(jQuery);
