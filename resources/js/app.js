// Progress pemeriksaan per website diperbarui tanpa memuat ulang halaman.
// Halaman menandai wadah dengan data-progress-url dan setiap website dengan data-target-progress.
const POLL_INTERVAL_MS = 2000;

// Sama dengan App\Support\Duration: "45 detik", "22 menit 23 detik", "1 jam 5 menit"
function formatDuration(totalSeconds) {
    const seconds = Math.max(0, Math.floor(totalSeconds));

    if (seconds < 60) {
        return `${seconds} detik`;
    }

    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const rest = seconds % 60;

    if (hours > 0) {
        return minutes > 0 ? `${hours} jam ${minutes} menit` : `${hours} jam`;
    }

    return rest > 0 ? `${minutes} menit ${rest} detik` : `${minutes} menit`;
}

// Sama dengan Duration::approximate: "± 10 menit" atau "< 1 menit"
function approximateDuration(seconds) {
    if (seconds < 60) {
        return '< 1 menit';
    }

    const minutes = Math.ceil(seconds / 60);

    return `± ${minutes >= 60 ? formatDuration(minutes * 60) : `${minutes} menit`}`;
}

// Lama berjalan dihitung dari nilai server terakhir ditambah waktu sejak nilai itu diterima
function setElapsed(element, seconds) {
    element.dataset.elapsed = seconds;
    element.dataset.elapsedAt = performance.now();
    element.textContent = formatDuration(seconds);
}

function tickElapsed() {
    document.querySelectorAll('[data-scan-time][data-running] [data-elapsed]').forEach((element) => {
        const since = Number(element.dataset.elapsedAt ?? performance.now());
        element.dataset.elapsedAt ??= since;
        element.textContent = formatDuration(Number(element.dataset.elapsed) + (performance.now() - since) / 1000);
    });
}

function updateTarget(target) {
    document.querySelectorAll(`[data-scan-time="${target.id}"]`).forEach((time) => {
        const elapsed = time.querySelector('[data-elapsed]');
        const remaining = time.querySelector('[data-remaining]');

        if (elapsed && target.elapsed !== null) {
            setElapsed(elapsed, target.elapsed);
        }

        if (remaining && target.remaining !== null) {
            remaining.textContent = approximateDuration(target.remaining);
        }
    });

    const row = document.querySelector(`[data-target-progress="${target.id}"]`);

    if (!row) {
        return false;
    }

    row.querySelector('[data-percent]').textContent = `${target.percent}%`;
    row.querySelector('[data-step]').textContent = target.step ?? target.status_label;

    const bar = row.querySelector('[data-bar]');
    bar.style.width = `${target.percent}%`;
    bar.className = `h-2 rounded-full transition-all duration-700 ${target.bar_class}`;
    bar.parentElement.setAttribute('aria-valuenow', target.percent);

    // Status berubah (contoh selesai): muat ulang supaya tautan hasil dan tombol export muncul
    return row.dataset.status !== target.status;
}

function watchProgress(container) {
    const poll = async () => {
        try {
            const response = await fetch(container.dataset.progressUrl, { headers: { Accept: 'application/json' } });

            if (response.ok) {
                const data = await response.json();
                const statusChanged = data.targets.map(updateTarget).some(Boolean);

                if (statusChanged || data.finished) {
                    window.location.reload();

                    return;
                }
            }
        } catch {
            // Server sedang restart atau koneksi terputus: coba lagi pada putaran berikutnya
        }

        setTimeout(poll, POLL_INTERVAL_MS);
    };

    setTimeout(poll, POLL_INTERVAL_MS);
}

document.querySelectorAll('[data-progress-url]').forEach(watchProgress);

if (document.querySelector('[data-scan-time][data-running]')) {
    tickElapsed();
    setInterval(tickElapsed, 1000);
}

// Riwayat: centang beberapa batch, semua di halaman ini, atau semua riwayat, lalu hapus setelah konfirmasi.
// Didaftarkan sebelum penahan klik ganda supaya konfirmasi yang dibatalkan tidak mengunci tombol.
function watchBulkSelection(form) {
    const items = [...form.querySelectorAll('[data-bulk-item]')];
    const pageToggle = form.querySelector('[data-bulk-all]');
    const everything = form.querySelector('input[name="all"]');
    const everythingButton = form.querySelector('[data-bulk-everything]');
    const counter = form.querySelector('[data-bulk-count]');
    const submit = form.querySelector('[data-bulk-submit]');
    const total = Number(form.dataset.bulkTotal);

    const checkedCount = () => items.filter((item) => item.checked).length;
    const selectedCount = () => (everything.value === '1' ? total : checkedCount());

    const update = () => {
        const checked = checkedCount();

        pageToggle.checked = items.length > 0 && checked === items.length;
        pageToggle.indeterminate = checked > 0 && checked < items.length;
        pageToggle.disabled = items.length === 0;
        // Pilihan semua riwayat muncul jika semua di halaman ini dipilih dan masih ada di halaman lain
        everythingButton.hidden = !(pageToggle.checked && total > items.length && everything.value !== '1');

        if (everything.value === '1') {
            counter.textContent = `Semua ${total} riwayat dipilih`;
        } else {
            counter.textContent = checked > 0 ? `${checked} dipilih` : 'Belum ada yang dipilih';
        }

        submit.disabled = selectedCount() === 0;
    };

    items.forEach((item) => {
        item.addEventListener('change', () => {
            everything.value = '0';
            update();
        });
    });

    pageToggle.addEventListener('change', () => {
        everything.value = '0';
        items.forEach((item) => {
            item.checked = pageToggle.checked;
        });
        update();
    });

    everythingButton.addEventListener('click', () => {
        everything.value = '1';
        update();
    });

    form.addEventListener('submit', (event) => {
        // Sudah dikirim: klik berikutnya ditolak penahan klik ganda tanpa konfirmasi ulang
        if (form.dataset.submitting) {
            return;
        }

        if (!window.confirm(form.dataset.confirm.replace('{count}', selectedCount()))) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }
    });

    // Tombol Back browser dapat mengembalikan centang lama
    window.addEventListener('pageshow', update);
    update();
}

document.querySelectorAll('[data-bulk-form]').forEach(watchBulkSelection);

// Klik ganda pada Mulai Pemeriksaan, Pindai Ulang, atau Hapus tidak boleh mengirim form dua kali
document.querySelectorAll('form[method="POST" i]').forEach((form) => {
    form.addEventListener('submit', (event) => {
        if (event.defaultPrevented) {
            return;
        }

        if (form.dataset.submitting) {
            event.preventDefault();

            return;
        }

        form.dataset.submitting = '1';
        form.querySelectorAll('button[type="submit"]').forEach((button) => {
            button.classList.add('pointer-events-none', 'opacity-60');
            button.setAttribute('aria-disabled', 'true');
        });
    });
});

// Kembali ke halaman lewat tombol Back browser (bfcache): form dapat dikirim lagi
window.addEventListener('pageshow', (event) => {
    if (!event.persisted) {
        return;
    }

    document.querySelectorAll('form[data-submitting]').forEach((form) => {
        delete form.dataset.submitting;
        form.querySelectorAll('button[aria-disabled]').forEach((button) => {
            button.classList.remove('pointer-events-none', 'opacity-60');
            button.removeAttribute('aria-disabled');
        });
    });
});

// Jumlah website yang diketik pada form pemeriksaan baru, contoh "3 website"
document.querySelectorAll('[data-url-count-for]').forEach((counter) => {
    const input = document.getElementById(counter.dataset.urlCountFor);

    if (!input) {
        return;
    }

    const update = () => {
        const count = input.value.split(/\r?\n/).filter((line) => line.trim() !== '').length;
        counter.textContent = count > 0 ? `${count} website` : '';
    };

    input.addEventListener('input', update);
    update();
});
