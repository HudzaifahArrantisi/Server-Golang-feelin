// api/submit-application.js
// Backend endpoint untuk Leapcell server
// Menangani: upload file (Cloudinary + Litterbox) + kirim email ke HR + return file URLs

import fetch from 'node-fetch';
import FormData from 'form-data';
import Busboy from 'busboy';

const CLOUDINARY_CLOUD_NAME    = process.env.CLOUDINARY_CLOUD_NAME    || 'diljtaox1';
const CLOUDINARY_UPLOAD_PRESET = process.env.CLOUDINARY_UPLOAD_PRESET || 'feelin_coffee_recruitment';
const HR_EMAIL                 = process.env.HR_EMAIL                  || 'hudzaifaharantisi17@gmail.com';
const ALLOW_ORIGIN             = process.env.ALLOW_ORIGIN              || '*';

// ─── CORS helper ─────────────────────────────────────────────────────────────
const setCORS = (res) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
};

// ─── Parse multipart form dari request ───────────────────────────────────────
const parseForm = (req) =>
  new Promise((resolve, reject) => {
    const bb = Busboy({ headers: req.headers });
    const fields = {};
    const files  = {}; // { fieldname: { buffer, filename, mimetype } }

    bb.on('field', (name, val) => { fields[name] = val; });

    bb.on('file', (name, stream, info) => {
      const chunks = [];
      stream.on('data', (d) => chunks.push(d));
      stream.on('end', () => {
        files[name] = {
          buffer:   Buffer.concat(chunks),
          filename: info.filename,
          mimetype: info.mimeType,
        };
      });
    });

    bb.on('finish', () => resolve({ fields, files }));
    bb.on('error',  reject);
    req.pipe(bb);
  });

// ─── Upload ke Cloudinary ─────────────────────────────────────────────────────
const uploadToCloudinary = async (fileObj, label) => {
  console.log(`☁️  [Cloudinary] ${label}: ${fileObj.filename}`);
  const form = new FormData();
  form.append('file', fileObj.buffer, {
    filename:    fileObj.filename,
    contentType: fileObj.mimetype,
  });
  form.append('upload_preset', CLOUDINARY_UPLOAD_PRESET);
  form.append('folder', 'feelin-coffee-recruitment');

  const res = await fetch(
    `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`,
    { method: 'POST', body: form }
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Cloudinary HTTP ${res.status}`);
  }
  const data = await res.json();
  console.log(`✅ [Cloudinary] ${label} → ${data.secure_url}`);
  return data.secure_url;
};

// ─── Upload ke Litterbox (72h) dengan fallback Catbox ────────────────────────
const uploadToLitterbox = async (fileObj, label) => {
  console.log(`📦 [Litterbox] ${label}: ${fileObj.filename}`);

  // Coba Litterbox
  try {
    const form = new FormData();
    form.append('reqtype',     'fileupload');
    form.append('time',        '72h');
    form.append('fileToUpload', fileObj.buffer, {
      filename:    fileObj.filename,
      contentType: fileObj.mimetype,
    });

    const res = await fetch(
      'https://litterbox.catbox.moe/resources/internals/api.php',
      { method: 'POST', body: form }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const url = (await res.text()).trim();
    if (url.startsWith('https://')) {
      console.log(`✅ [Litterbox] ${label} → ${url}`);
      return url;
    }
    throw new Error(`Respons tidak valid: "${url}"`);
  } catch (litterErr) {
    console.warn(`⚠️  Litterbox gagal (${litterErr.message}), fallback Catbox...`);

    const form2 = new FormData();
    form2.append('reqtype',     'fileupload');
    form2.append('fileToUpload', fileObj.buffer, {
      filename:    fileObj.filename,
      contentType: fileObj.mimetype,
    });
    const res2 = await fetch('https://catbox.moe/user/api.php', {
      method: 'POST', body: form2,
    });
    if (!res2.ok) throw new Error(`Catbox HTTP ${res2.status}`);
    const url2 = (await res2.text()).trim();
    if (url2.startsWith('https://')) {
      console.log(`✅ [Catbox] ${label} → ${url2}`);
      return url2;
    }
    throw new Error(`Catbox respons tidak valid: "${url2}"`);
  }
};

// ─── Kirim email ke HR via FormSubmit ────────────────────────────────────────
const sendEmailToHR = async (fields, urls) => {
  const form = new FormData();
  form.append('_subject',           `📋 Lamaran Baru: ${fields.position} - ${fields.fullName}`);
  form.append('Posisi',             fields.position);
  form.append('Nama_Lengkap',       fields.fullName);
  form.append('Email',              fields.email);
  form.append('Telepon',            fields.phone);
  form.append('Usia',             `${fields.age} tahun`);
  form.append('Alamat',             fields.address);
  form.append('Pendidikan',         fields.education);
  form.append('Pengalaman',         fields.experience    || 'Tidak ada');
  form.append('Informasi_Tambahan', fields.additionalInfo || '-');
  form.append('Tanggal_Melamar',    new Date().toLocaleString('id-ID'));
  form.append('CV',         urls.cvUrl          || 'Tidak ada');
  form.append('Foto',       urls.photoUrl       || 'Tidak ada');
  form.append('KTP',        urls.ktpUrl         || 'Tidak ada');
  form.append('Sertifikat', urls.certificateUrl || 'Tidak ada');
  form.append('_captcha',   'false');
  form.append('_template',  'table');

  const res = await fetch(`https://formsubmit.co/ajax/${HR_EMAIL}`, {
    method:  'POST',
    headers: { Accept: 'application/json' },
    body:    form,
  });
  if (!res.ok) throw new Error(`FormSubmit HTTP ${res.status}`);
  return res.json();
};

// ─── Main handler ─────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  setCORS(res);

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')
    return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { fields, files } = await parseForm(req);
    console.log('📨 Submit lamaran:', fields.fullName, '→', fields.position);

    const getExt = (fn = '') => fn.split('.').pop().toLowerCase();

    // ── Upload semua file secara paralel ──────────────────────────────────────
    const [cvUrl, photoUrl, ktpUrl, certificateUrl] = await Promise.all([
      // CV → field link dulu, kalau ada file baru upload
      fields.cvLink
        ? Promise.resolve(fields.cvLink)
        : files.cvFile
          ? uploadToLitterbox(files.cvFile, 'CV')
          : Promise.resolve(null),

      fields.photoLink
        ? Promise.resolve(fields.photoLink)
        : files.photoFile
          ? uploadToCloudinary(files.photoFile, 'Foto Diri')
          : Promise.resolve(null),

      fields.ktpLink
        ? Promise.resolve(fields.ktpLink)
        : files.ktpFile
          ? uploadToCloudinary(files.ktpFile, 'KTP')
          : Promise.resolve(null),

      fields.certificateLink
        ? Promise.resolve(fields.certificateLink)
        : files.certificateFile
          ? (['pdf'].includes(getExt(files.certificateFile.filename))
              ? uploadToLitterbox(files.certificateFile, 'Sertifikat')
              : uploadToCloudinary(files.certificateFile, 'Sertifikat'))
          : Promise.resolve(null),
    ]);

    const urls = { cvUrl, photoUrl, ktpUrl, certificateUrl };
    console.log('📊 URLs:', urls);

    // ── Kirim email ke HR ──────────────────────────────────────────────────────
    let emailSuccess = false;
    try {
      await sendEmailToHR(fields, urls);
      emailSuccess = true;
      console.log('✅ Email HR terkirim');
    } catch (emailErr) {
      console.warn('⚠️  Email HR gagal:', emailErr.message);
    }

    return res.status(200).json({
      success: true,
      emailSuccess,
      fileUrls: urls,
      message: 'Lamaran berhasil diproses',
    });

  } catch (err) {
    console.error('❌ submit-application error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}