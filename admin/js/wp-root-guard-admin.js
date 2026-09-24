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
			var percentText = document.getElementById('rg-scan-percentage');
			var progressBar = document.getElementById('rg-scan-bar');
			var currentItemText = document.getElementById('rg-scan-current-item');

			// Jika tampilan kartu antrean interaktif tersedia di halaman
			if (inlineCard) {
				if (statusCard) statusCard.style.display = 'none';
				if (summaryCard) summaryCard.style.display = 'none';
				if (actionsBar) actionsBar.style.display = 'none';
				inlineCard.classList.remove('hidden');
				inlineCard.style.display = 'block';

				$.post(wpRootGuard.ajaxUrl, {
					action: 'wp_root_guard_get_scan_queue',
					nonce: wpRootGuard.nonce,
					security: wpRootGuard.nonce
				}, function (response) {
					if (response.success && response.data && response.data.queue) {
						var queue = response.data.queue;
						var total = queue.length;
						var current = 0;

						var interval = setInterval(function () {
							if (current < total) {
								var item = queue[current];
								var itemText = typeof item === 'object' ? item.name : item;
								var prefix = (typeof item === 'object' && item.type === 'folder') ? '📂 Folder: ' :
									((typeof item === 'object' && item.type === 'core') ? '🛡️ Core File: ' : '📄 File: ');
								if (currentItemText) currentItemText.innerText = prefix + itemText;

								var percent = Math.floor((current / total) * 90);
								if (percentText) percentText.innerText = percent + '%';
								if (progressBar) progressBar.style.width = percent + '%';

								current++;
							} else {
								clearInterval(interval);
								if (currentItemText) currentItemText.innerText = '🛡️ Menganalisis hasil & tanda tangan malware...';

								$.post(wpRootGuard.ajaxUrl, {
									action: 'wp_root_guard_run_scan',
									nonce: wpRootGuard.nonce,
									security: wpRootGuard.nonce
								}, function (scanResponse) {
									if (scanResponse.success) {
										if (percentText) percentText.innerText = '100%';
										if (progressBar) progressBar.style.width = '100%';
										if (currentItemText) currentItemText.innerText = '✅ Pemindaian Selesai! Memuat ulang halaman...';

										setTimeout(function () {
											window.location.href = '?page=wp-root-guard&tab=dashboard&message=scanned';
										}, 800);
									} else {
										alert((scanResponse.data && scanResponse.data.message) ? scanResponse.data.message : errorText);
										$btn.prop('disabled', false).text('Pindai Sekarang (Scan Now)');
									}
								}).fail(function () {
									WPRootGuard.submitRgAction('scan_now');
								});
							}
						}, 30);
					} else {
						WPRootGuard.submitRgAction('scan_now');
					}
				}).fail(function () {
					WPRootGuard.submitRgAction('scan_now');
				});
			} else {
				// Mode standar dengan progress bar
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
							if ($progress.length) {
								$progress.find('.rg-progress-fill').css('width', '100%');
							}
							setTimeout(function () {
								window.location.reload();
							}, 500);
						} else {
							alert((response.data && response.data.message) ? response.data.message : errorText);
							$btn.prop('disabled', false).text('Scan Now');
						}
					})
					.fail(function () {
						alert(errorText);
						$btn.prop('disabled', false).text('Scan Now');
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

	$(document).ready(function () {
		WPRootGuard.init();
	});
})(jQuery);
