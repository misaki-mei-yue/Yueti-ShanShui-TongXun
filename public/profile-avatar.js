'use strict';
(() => {
  let options = {}, editor = 0;
  function init(value) { options = value; }
  function open() {
    const person = options.getUser(); if (!person) return;
    const generation = ++editor, accountId = String(person.id), initial = options.safeURL(person.avatarUrl,'/api/avatars/');
    let dataUrl = null, loading = false, selection = 0, editorNode, bitmap = null, zoom = 1, x = 0, y = 0, drag = null;
    const isCurrent = () => editor === generation && String(options.getUser()?.id) === accountId && document.getElementById('dialog')?.open && document.getElementById('avatar-preview') === editorNode;
    options.openDialog('我的头像',`<div class="profile-avatar-editor"><div class="profile-avatar-preview" id="avatar-preview">${initial ? `<img class="avatar-image" src="${options.escape(initial)}" alt="当前头像">` : options.escape((person.displayName || '我').slice(0,1))}</div><div id="avatar-crop-tools" hidden><label class="avatar-zoom-label">缩放 <input id="avatar-zoom" type="range" min="1" max="4" step="0.01" value="1"><output id="avatar-zoom-value">1.00×</output></label><button class="secondarybtn" id="avatar-center">重新居中</button></div><p class="profile-avatar-help">选择图片后拖动调整位置，滑动缩放。</p><p class="dialogcopy profile-avatar-copy">PNG、JPEG、WebP；保存方形头像并同步到账户。头像属于公开资料，服务器可见。</p><input id="avatar-file" type="file" accept="image/png,image/jpeg,image/webp" hidden><div class="profile-avatar-tools"><button class="secondarybtn" id="avatar-choose">选择图片</button><button class="secondarybtn" id="avatar-reset">恢复默认</button></div><p id="avatar-status" class="profile-avatar-status" role="status"></p><div class="dialogactions"><button class="secondarybtn" id="avatar-cancel">取消</button><button class="sendbtn" id="avatar-save" disabled>保存头像</button></div></div>`);
    const $ = id => document.getElementById(id), dialog = $('dialog'); editorNode = $('avatar-preview');
    const cleanup = () => { bitmap?.close(); bitmap = null; drag = null; dialog.removeEventListener('close',cleanup); }; dialog.addEventListener('close',cleanup);
    function draw() {
      if (!bitmap || !isCurrent()) return;
      const side = Math.min(bitmap.width,bitmap.height) / zoom;
      x = Math.min(bitmap.width - side / 2,Math.max(side / 2,x)); y = Math.min(bitmap.height - side / 2,Math.max(side / 2,y));
      const ctx = $('avatar-crop-canvas').getContext('2d'); ctx.fillStyle = '#fff'; ctx.fillRect(0,0,384,384); ctx.drawImage(bitmap,x - side / 2,y - side / 2,side,side,0,0,384,384);
      $('avatar-zoom-value').value = `${zoom.toFixed(2)}×`;
    }
    function setZoom(value) { zoom = Math.min(4,Math.max(1,value)); $('avatar-zoom').value = String(zoom); draw(); }
    function installCanvas() {
      const canvas = document.createElement('canvas'); canvas.width = canvas.height = 384; canvas.id = 'avatar-crop-canvas'; canvas.tabIndex = 0; canvas.setAttribute('role','img'); canvas.setAttribute('aria-label','头像取景框，拖动或用方向键移动');
      editorNode.classList.add('profile-avatar-cropping'); editorNode.replaceChildren(canvas); $('avatar-crop-tools').hidden = false;
      canvas.onpointerdown = event => { if (!bitmap || loading || event.button !== 0) return; canvas.setPointerCapture(event.pointerId); drag = {id:event.pointerId,x:event.clientX,y:event.clientY,cx:x,cy:y}; event.preventDefault(); };
      canvas.onpointermove = event => { if (!drag || drag.id !== event.pointerId || !bitmap || loading) return; const scale = Math.min(bitmap.width,bitmap.height) / zoom / canvas.getBoundingClientRect().width; x = drag.cx - (event.clientX - drag.x) * scale; y = drag.cy - (event.clientY - drag.y) * scale; draw(); };
      canvas.onpointerup = canvas.onpointercancel = () => { drag = null; };
      canvas.onwheel = event => { if (!bitmap || loading) return; event.preventDefault(); setZoom(zoom + (event.deltaY < 0 ? .1 : -.1)); };
      canvas.onkeydown = event => { if (!bitmap || loading) return; const step = Math.min(bitmap.width,bitmap.height) / zoom / (event.shiftKey ? 10 : 40); if (event.key === 'ArrowLeft') x -= step; else if (event.key === 'ArrowRight') x += step; else if (event.key === 'ArrowUp') y -= step; else if (event.key === 'ArrowDown') y += step; else return; event.preventDefault(); draw(); };
      draw();
    }
    $('avatar-zoom').oninput = event => { if (!loading) setZoom(Number(event.target.value)); };
    $('avatar-center').onclick = () => { if (!bitmap || loading) return; x = bitmap.width / 2; y = bitmap.height / 2; setZoom(1); };
    $('avatar-cancel').onclick = () => { editor++; dialog.close(); };
    $('avatar-choose').onclick = () => { $('avatar-file').value = ''; $('avatar-file').click(); };
    $('avatar-reset').onclick = () => { if (loading) return; selection++; bitmap?.close(); bitmap = null; dataUrl = ''; editorNode.classList.remove('profile-avatar-cropping'); editorNode.textContent = (person.displayName || '我').slice(0,1); $('avatar-crop-tools').hidden = true; $('avatar-status').textContent = '保存后恢复默认头像。'; $('avatar-save').disabled = false; };
    $('avatar-file').onchange = async event => {
      const file = event.target.files?.[0]; if (!file) return;
      if (!['image/png','image/jpeg','image/webp'].includes(file.type)) { $('avatar-status').textContent = '请选择 PNG、JPEG 或 WebP 图片。'; return; }
      if (file.size > 12 * 1024 * 1024) { $('avatar-status').textContent = '原图请小于 12 MB。'; return; }
      const ticket = ++selection; loading = true; $('avatar-save').disabled = true; $('avatar-reset').disabled = true; $('avatar-status').textContent = '正在读取原图…'; let decoded;
      try {
        decoded = await createImageBitmap(file,{imageOrientation:'from-image'}); if (!isCurrent() || ticket !== selection) return;
        if (!decoded.width || !decoded.height || decoded.width * decoded.height > 60000000) throw new Error('图片尺寸过大，请换一张较小的图片。');
        bitmap?.close(); bitmap = decoded; decoded = null; dataUrl = null; zoom = 1; x = bitmap.width / 2; y = bitmap.height / 2; $('avatar-zoom').value = '1'; installCanvas(); $('avatar-status').textContent = '拖动选择位置，缩放后点击保存。';
      } catch (error) { if (isCurrent() && ticket === selection) $('avatar-status').textContent = error.message || '无法读取图片，请重新选择。'; }
      finally { decoded?.close(); if (isCurrent() && ticket === selection) { loading = false; $('avatar-reset').disabled = false; $('avatar-save').disabled = !bitmap && dataUrl === null; } }
    };
    $('avatar-save').onclick = async () => {
      if (loading || (!bitmap && dataUrl === null) || !isCurrent()) return;
      if (bitmap) { draw(); dataUrl = $('avatar-crop-canvas').toDataURL('image/jpeg',.9); }
      loading = true; for (const id of ['avatar-save','avatar-choose','avatar-reset','avatar-zoom','avatar-center']) $(id).disabled = true; $('avatar-status').textContent = '正在同步头像…';
      try { const result = await options.api('/api/me/avatar',{method:'PUT',body:{dataUrl}}); if (!isCurrent()) return; options.onChange(result.user); dialog.close(); editor++; options.toast('头像已同步到你的账户。'); }
      catch (error) { if (isCurrent()) $('avatar-status').textContent = error.message; }
      finally { if (isCurrent()) { loading = false; for (const id of ['avatar-save','avatar-choose','avatar-reset','avatar-zoom','avatar-center']) $(id).disabled = false; } }
    };
  }
  window.YuetiAvatar = Object.freeze({init,open});
})();
