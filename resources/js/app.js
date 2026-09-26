// Progress pemeriksaan per website diperbarui tanpa memuat ulang halaman.
// Halaman menandai wadah dengan data-progress-url dan setiap website dengan data-target-progress.
const POLL_INTERVAL_MS = 2000;

function updateTarget(target) {
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
