(() => {
  const modal = document.getElementById('avatar-modal');
  const trigger = document.getElementById('open-avatar-modal');
  const closeButton = document.getElementById('close-avatar-modal');
  const picker = document.getElementById('avatar');
  const image = document.getElementById('avatar-modal-image');
  const fallback = document.getElementById('avatar-modal-fallback');
  const message = document.getElementById('avatar-preview-message');
  const originalSrc = image?.getAttribute('src') || '';
  const closeModal = () => { if(modal) modal.hidden = true; trigger?.focus(); };
  trigger?.addEventListener('click', () => { modal.hidden = false; closeButton?.focus(); });
  closeButton?.addEventListener('click', closeModal);
  modal?.addEventListener('click', e => { if(e.target === modal) closeModal(); });
  document.addEventListener('keydown', e => { if(e.key === 'Escape' && modal && !modal.hidden) closeModal(); });
  picker?.addEventListener('change', () => {
    const file = picker.files?.[0];
    if (!file) return;
    if (!['image/jpeg','image/png','image/webp'].includes(file.type) || file.size > 3*1024*1024) {
      picker.value = '';
      if(message) message.textContent = 'Select JPG, PNG or WebP under 3 MB / اختار صورة أقل من 3 ميغابايت';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      image.onload = () => {
        image.hidden = false;
        if(fallback) fallback.hidden = true;
        if(message) message.textContent = 'Preview only. Click Save picture to apply / معاينة فقط، اضغط حفظ الصورة لاعتمادها';
      };
      image.onerror = () => {
        image.hidden = !originalSrc;
        if(originalSrc) image.src = originalSrc;
        if(fallback) fallback.hidden = !!originalSrc;
        if(message) message.textContent = 'Unable to preview image / تعذر عرض الصورة';
      };
      image.src = reader.result;
      image.hidden = false;
      if(fallback) fallback.hidden = true;
    };
    reader.onerror = () => { if(message) message.textContent = 'Unable to read image / تعذر قراءة الصورة'; };
    reader.readAsDataURL(file);
  });
  const open = document.getElementById('open-username-confirm');
  const dialog = document.getElementById('username-confirm');
  const cancel = document.getElementById('cancel-username-confirm');
  const password = document.getElementById('username_password');
  const username = document.getElementById('username');
  if (open && dialog && password && username) {
    const close = () => { dialog.hidden = true; password.disabled = true; password.required = false; password.value = ''; open.focus(); };
    open.addEventListener('click', () => {
      if (!username.reportValidity()) return;
      dialog.hidden = false; password.disabled = false; password.required = true; password.focus();
    });
    cancel?.addEventListener('click', close);
    dialog.addEventListener('click', e => { if (e.target === dialog) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !dialog.hidden) close(); });
  }
})();
