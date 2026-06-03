/**
 * PetMate — Güvenli Backend (server.js)
 * 
 * Değişiklikler:
 *  - bcrypt ile şifre hash'leme
 *  - .env ile credential yönetimi
 *  - JWT tabanlı session (basit token)
 *  - Admin endpoint'leri için auth middleware
 *  - Rate limiting (express-rate-limit)
 *  - Helmet ile HTTP header güvenliği
 *  - Input sanitizasyonu
 *  - Yeni tablolar: Pets, Vaccinations, MedicalRecords, Appointments, Reminders
 * 
 * Kurulum:
 *   npm install express mssql bcryptjs jsonwebtoken dotenv helmet express-rate-limit
 */

require('dotenv').config();

const express    = require('express');
const sql        = require('mssql');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const app = express();

/* ══════════════════════════════════════════
   GÜVENLİK MİDDLEWARE'LERİ
══════════════════════════════════════════ */
app.use(helmet());
app.use(express.static('public'));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Rate limiting — tüm API'ye
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100,
    message: 'Çok fazla istek gönderildi. Lütfen 15 dakika bekleyin.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Auth endpoint'lerine daha sıkı limit
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Çok fazla giriş denemesi. Lütfen 15 dakika bekleyin.',
});

app.use('/api/', apiLimiter);
app.use('/kullanici-giris', authLimiter);
app.use('/kullanici-kayit', authLimiter);

/* ══════════════════════════════════════════
   VERİTABANI BAĞLANTISI
   .env dosyasında tanımla:
   DB_USER=sa
   DB_PASS=SifreninizBuraya
   DB_SERVER=MELISA
   DB_NAME=PetMateDB
   JWT_SECRET=cok_gizli_bir_anahtar_buraya
══════════════════════════════════════════ */
const config = {
    user:     process.env.DB_USER     || 'sa',
    password: process.env.DB_PASS     || 'Sifre123.',
    server:   process.env.DB_SERVER   || 'MELISA',
    database: process.env.DB_NAME     || 'PetMateDB',
    options: {
        encrypt: true,
        trustServerCertificate: true,
    },
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000,
    },
};

// Connection pool — her istekte yeniden bağlanmak yerine pool kullan
let pool;
async function getPool() {
    if (!pool) {
        pool = await sql.connect(config);
    }
    return pool;
}

/* ══════════════════════════════════════════
   AUTH MİDDLEWARE
══════════════════════════════════════════ */
const JWT_SECRET = process.env.JWT_SECRET || 'degistirmeniz_gereken_gizli_anahtar';

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"
    if (!token) return res.status(401).json({ error: 'Giriş yapmanız gerekiyor.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(403).json({ error: 'Oturum süresi dolmuş. Tekrar giriş yapın.' });
    }
}

// Admin kontrolü (örnek: rol bazlı)
function adminMiddleware(req, res, next) {
    if (!req.user || req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Bu işlem için yetkiniz yok.' });
    }
    next();
}

/* ══════════════════════════════════════════
   YARDIMCI FONKSİYONLAR
══════════════════════════════════════════ */
function sanitizeStr(val, maxLen = 255) {
    if (val === undefined || val === null) return null;
    return String(val).trim().substring(0, maxLen);
}

function sanitizeInt(val) {
    const n = parseInt(val);
    return isNaN(n) ? null : n;
}

/* ══════════════════════════════════════════
   ═══════  MEVCUT İLAN ENDPOINT'LERİ  ══════
══════════════════════════════════════════ */

// İlan ekle
app.post('/ilan-ekle', async (req, res) => {
    if (!req.body || Object.keys(req.body).length === 0)
        return res.status(400).json({ error: 'Veri ulaşmıyor.' });
    try {
        const p = await getPool();
        await p.request()
            .input('ilanTuru',   sql.NVarChar(50),   sanitizeStr(req.body.ilanTuru, 50))
            .input('hayvanTuru', sql.NVarChar(50),   sanitizeStr(req.body.hayvanTuru, 50))
            .input('hayvanAdi',  sql.NVarChar(100),  sanitizeStr(req.body.hayvanAdi, 100))
            .input('irk',        sql.NVarChar(100),  sanitizeStr(req.body.irk, 100))
            .input('yas',        sql.Int,            sanitizeInt(req.body.yas))
            .input('cinsiyet',   sql.NVarChar(20),   sanitizeStr(req.body.cinsiyet, 20))
            .input('renk',       sql.NVarChar(100),  sanitizeStr(req.body.renk, 100))
            .input('sehir',      sql.NVarChar(100),  sanitizeStr(req.body.sehir, 100))
            .input('aciklama',   sql.NVarChar(2000), sanitizeStr(req.body.aciklama, 2000))
            .input('iletisim',   sql.NVarChar(100),  sanitizeStr(req.body.iletisim, 100))
            .query(`INSERT INTO dbo.HayvanIlanlari
                    (IlanTuru,HayvanTuru,HayvanAdi,Irk,Yas,Cinsiyet,Renk,Sehir,Aciklama,Iletisim)
                    VALUES
                    (@ilanTuru,@hayvanTuru,@hayvanAdi,@irk,@yas,@cinsiyet,@renk,@sehir,@aciklama,@iletisim)`);
        res.json({ success: true, message: 'İlan başarıyla kaydedildi.' });
    } catch (err) {
        console.error('SQL Hatası (ilan-ekle):', err.message);
        res.status(500).json({ error: 'Veritabanı hatası oluştu.' });
    }
});

// İlanları getir
app.get('/ilanlari-getir', async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request()
            .query('SELECT * FROM dbo.HayvanIlanlari ORDER BY Id DESC');
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL Hatası (ilanlari-getir):', err.message);
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

// İlan sil — AUTH GEREKTİRİR
app.delete('/ilan-sil/:id', authMiddleware, adminMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Geçersiz ID.' });
    try {
        const p = await getPool();
        await p.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM dbo.HayvanIlanlari WHERE Id = @id');
        res.json({ success: true, message: 'İlan silindi.' });
    } catch (err) {
        console.error('SQL Hatası (ilan-sil):', err.message);
        res.status(500).json({ error: 'Silme hatası.' });
    }
});

// Öne çıkan ilanları getir
app.get('/one-cikan-ilanlar', async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request().query(`
            SELECT h.*
            FROM dbo.HayvanIlanlari h
            INNER JOIN dbo.OneCikanIlanlar o ON h.Id = o.IlanId
            ORDER BY o.Sira ASC
        `);
        res.json(result.recordset);
    } catch {
        res.json([]);
    }
});

// Öne çıkan ilanları güncelle — AUTH GEREKTİRİR
app.post('/one-cikan-guncelle', authMiddleware, adminMiddleware, async (req, res) => {
    const { ilanIds } = req.body;
    if (!Array.isArray(ilanIds)) return res.status(400).json({ error: 'Geçersiz format.' });
    if (ilanIds.length > 6)     return res.status(400).json({ error: 'En fazla 6 ilan seçilebilir.' });
    try {
        const p = await getPool();
        await p.request().query('DELETE FROM dbo.OneCikanIlanlar');
        for (let i = 0; i < ilanIds.length; i++) {
            const id = sanitizeInt(ilanIds[i]);
            if (!id) continue;
            await p.request()
                .input('ilanId', sql.Int, id)
                .input('sira',   sql.Int, i + 1)
                .query('INSERT INTO dbo.OneCikanIlanlar (IlanId, Sira) VALUES (@ilanId, @sira)');
        }
        res.json({ success: true, message: 'Güncellendi.' });
    } catch (err) {
        console.error('SQL Hatası (one-cikan-guncelle):', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.get('/one-cikan-idler', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request()
            .query('SELECT IlanId FROM dbo.OneCikanIlanlar ORDER BY Sira ASC');
        res.json(result.recordset.map(r => r.IlanId));
    } catch {
        res.json([]);
    }
});

/* ══════════════════════════════════════════
   ═══════  KULLANICI YÖNETİMİ  ══════════
══════════════════════════════════════════ */

// Kayıt — bcrypt ile hash
app.post('/kullanici-kayit', async (req, res) => {
    const { kullanici, sifre, email } = req.body;
    if (!kullanici || !sifre)
        return res.status(400).json({ error: 'Zorunlu alanlar eksik.' });
    if (kullanici.length < 3)
        return res.status(400).json({ error: 'Kullanıcı adı en az 3 karakter olmalı.' });
    if (sifre.length < 8)
        return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı.' });

    try {
        const p = await getPool();
        const kontrol = await p.request()
            .input('kullanici', sql.NVarChar(100), kullanici)
            .query('SELECT COUNT(*) AS sayi FROM dbo.Kullanicilar WHERE KullaniciAdi=@kullanici');
        if (kontrol.recordset[0].sayi > 0)
            return res.status(409).json({ error: 'Bu kullanıcı adı zaten alınmış.' });

        const hashedSifre = await bcrypt.hash(sifre, 12);
        await p.request()
            .input('kullanici', sql.NVarChar(100), kullanici)
            .input('sifre',     sql.NVarChar(255), hashedSifre)
            .input('email',     sql.NVarChar(255), sanitizeStr(email, 255))
            .query(`INSERT INTO dbo.Kullanicilar (KullaniciAdi, Sifre, Email, Rol, OlusturulmaTarihi)
                    VALUES (@kullanici, @sifre, @email, 'user', GETDATE())`);
        res.json({ success: true, message: 'Kayıt başarılı.' });
    } catch (err) {
        console.error('SQL Hatası (kullanici-kayit):', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// Giriş — bcrypt karşılaştırma + JWT
app.post('/kullanici-giris', async (req, res) => {
    const { kullanici, sifre } = req.body;
    if (!kullanici || !sifre)
        return res.status(400).json({ error: 'Zorunlu alanlar eksik.' });
    try {
        const p = await getPool();
        const result = await p.request()
            .input('kullanici', sql.NVarChar(100), kullanici)
            .query('SELECT KullaniciId, KullaniciAdi, Sifre, Rol FROM dbo.Kullanicilar WHERE KullaniciAdi=@kullanici');

        if (result.recordset.length === 0)
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });

        const user = result.recordset[0];
        const sifreUyumu = await bcrypt.compare(sifre, user.Sifre);
        if (!sifreUyumu)
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });

        const token = jwt.sign(
            { id: user.KullaniciId, kullanici: user.KullaniciAdi, rol: user.Rol },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ success: true, token, kullanici: user.KullaniciAdi, rol: user.Rol });
    } catch (err) {
        console.error('SQL Hatası (kullanici-giris):', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═════  PET MANAGEMENT ENDPOINT'LERİ  ════
══════════════════════════════════════════ */

// Kullanıcının hayvanlarını getir
app.get('/api/pets', authMiddleware, async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request()
            .input('userId', sql.Int, req.user.id)
            .query('SELECT * FROM dbo.Pets WHERE UserId=@userId AND IsActive=1 ORDER BY CreatedAt DESC');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

// Hayvan ekle
app.post('/api/pets', authMiddleware, async (req, res) => {
    const { name, species, breed, birthDate, weight, gender, color, photoUrl, notes } = req.body;
    if (!name || !species)
        return res.status(400).json({ error: 'Ad ve tür zorunludur.' });
    try {
        const p = await getPool();
        const result = await p.request()
            .input('userId',    sql.Int,          req.user.id)
            .input('name',      sql.NVarChar(100), sanitizeStr(name, 100))
            .input('species',   sql.NVarChar(50),  sanitizeStr(species, 50))
            .input('breed',     sql.NVarChar(100), sanitizeStr(breed, 100))
            .input('birthDate', sql.Date,          birthDate || null)
            .input('weight',    sql.Decimal(5,2),  parseFloat(weight) || null)
            .input('gender',    sql.NVarChar(20),  sanitizeStr(gender, 20))
            .input('color',     sql.NVarChar(100), sanitizeStr(color, 100))
            .input('photoUrl',  sql.NVarChar(500), sanitizeStr(photoUrl, 500))
            .input('notes',     sql.NVarChar(2000),sanitizeStr(notes, 2000))
            .query(`INSERT INTO dbo.Pets
                    (UserId,Name,Species,Breed,BirthDate,Weight,Gender,Color,PhotoUrl,Notes,IsActive,CreatedAt)
                    OUTPUT INSERTED.Id
                    VALUES (@userId,@name,@species,@breed,@birthDate,@weight,@gender,@color,@photoUrl,@notes,1,GETDATE())`);
        res.status(201).json({ success: true, id: result.recordset[0].Id });
    } catch (err) {
        console.error('SQL Hatası (pets POST):', err.message);
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

// Hayvan güncelle
app.put('/api/pets/:id', authMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Geçersiz ID.' });
    const { name, species, breed, birthDate, weight, gender, color, photoUrl, notes } = req.body;
    try {
        const p = await getPool();
        await p.request()
            .input('id',        sql.Int,           id)
            .input('userId',    sql.Int,           req.user.id)
            .input('name',      sql.NVarChar(100), sanitizeStr(name, 100))
            .input('species',   sql.NVarChar(50),  sanitizeStr(species, 50))
            .input('breed',     sql.NVarChar(100), sanitizeStr(breed, 100))
            .input('birthDate', sql.Date,          birthDate || null)
            .input('weight',    sql.Decimal(5,2),  parseFloat(weight) || null)
            .input('gender',    sql.NVarChar(20),  sanitizeStr(gender, 20))
            .input('color',     sql.NVarChar(100), sanitizeStr(color, 100))
            .input('photoUrl',  sql.NVarChar(500), sanitizeStr(photoUrl, 500))
            .input('notes',     sql.NVarChar(2000),sanitizeStr(notes, 2000))
            .query(`UPDATE dbo.Pets
                    SET Name=@name,Species=@species,Breed=@breed,BirthDate=@birthDate,
                        Weight=@weight,Gender=@gender,Color=@color,PhotoUrl=@photoUrl,Notes=@notes
                    WHERE Id=@id AND UserId=@userId`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Güncelleme hatası.' });
    }
});

// Hayvan sil (soft delete)
app.delete('/api/pets/:id', authMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Geçersiz ID.' });
    try {
        const p = await getPool();
        await p.request()
            .input('id',     sql.Int, id)
            .input('userId', sql.Int, req.user.id)
            .query('UPDATE dbo.Pets SET IsActive=0 WHERE Id=@id AND UserId=@userId');
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Silme hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  AŞI TAKİBİ  ══════════════════
══════════════════════════════════════════ */

app.get('/api/pets/:petId/vaccinations', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    try {
        const p = await getPool();
        const result = await p.request()
            .input('petId',  sql.Int, petId)
            .input('userId', sql.Int, req.user.id)
            .query(`SELECT v.* FROM dbo.Vaccinations v
                    INNER JOIN dbo.Pets pt ON v.PetId=pt.Id
                    WHERE v.PetId=@petId AND pt.UserId=@userId
                    ORDER BY v.VaccineDate DESC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/pets/:petId/vaccinations', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    const { vaccineName, vaccineDate, nextDate, vetName, notes } = req.body;
    if (!vaccineName || !vaccineDate)
        return res.status(400).json({ error: 'Aşı adı ve tarih zorunludur.' });
    try {
        const p = await getPool();
        await p.request()
            .input('petId',       sql.Int,           petId)
            .input('vaccineName', sql.NVarChar(200),  sanitizeStr(vaccineName, 200))
            .input('vaccineDate', sql.Date,            vaccineDate)
            .input('nextDate',    sql.Date,            nextDate || null)
            .input('vetName',     sql.NVarChar(200),  sanitizeStr(vetName, 200))
            .input('notes',       sql.NVarChar(1000), sanitizeStr(notes, 1000))
            .query(`INSERT INTO dbo.Vaccinations (PetId,VaccineName,VaccineDate,NextDate,VetName,Notes,CreatedAt)
                    VALUES (@petId,@vaccineName,@vaccineDate,@nextDate,@vetName,@notes,GETDATE())`);
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  SAĞLIK KAYITLARI  ════════════
══════════════════════════════════════════ */

app.get('/api/pets/:petId/medical', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    try {
        const p = await getPool();
        const result = await p.request()
            .input('petId',  sql.Int, petId)
            .input('userId', sql.Int, req.user.id)
            .query(`SELECT m.* FROM dbo.MedicalRecords m
                    INNER JOIN dbo.Pets pt ON m.PetId=pt.Id
                    WHERE m.PetId=@petId AND pt.UserId=@userId
                    ORDER BY m.RecordDate DESC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/pets/:petId/medical', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    const { recordDate, recordType, diagnosis, treatment, prescription, vetName, clinicName, cost, notes } = req.body;
    if (!recordDate || !recordType)
        return res.status(400).json({ error: 'Tarih ve kayıt türü zorunludur.' });
    try {
        const p = await getPool();
        await p.request()
            .input('petId',       sql.Int,           petId)
            .input('recordDate',  sql.Date,           recordDate)
            .input('recordType',  sql.NVarChar(100),  sanitizeStr(recordType, 100))
            .input('diagnosis',   sql.NVarChar(1000), sanitizeStr(diagnosis, 1000))
            .input('treatment',   sql.NVarChar(1000), sanitizeStr(treatment, 1000))
            .input('prescription',sql.NVarChar(1000), sanitizeStr(prescription, 1000))
            .input('vetName',     sql.NVarChar(200),  sanitizeStr(vetName, 200))
            .input('clinicName',  sql.NVarChar(200),  sanitizeStr(clinicName, 200))
            .input('cost',        sql.Decimal(10,2),  parseFloat(cost) || null)
            .input('notes',       sql.NVarChar(2000), sanitizeStr(notes, 2000))
            .query(`INSERT INTO dbo.MedicalRecords
                    (PetId,RecordDate,RecordType,Diagnosis,Treatment,Prescription,VetName,ClinicName,Cost,Notes,CreatedAt)
                    VALUES (@petId,@recordDate,@recordType,@diagnosis,@treatment,@prescription,
                            @vetName,@clinicName,@cost,@notes,GETDATE())`);
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  RANDEVULAR  ═══════════════════
══════════════════════════════════════════ */

app.get('/api/appointments', authMiddleware, async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request()
            .input('userId', sql.Int, req.user.id)
            .query(`SELECT a.*, pt.Name AS PetName, pt.Species AS PetSpecies
                    FROM dbo.Appointments a
                    INNER JOIN dbo.Pets pt ON a.PetId=pt.Id
                    WHERE pt.UserId=@userId AND a.AppointmentDate >= CAST(GETDATE() AS DATE)
                    ORDER BY a.AppointmentDate ASC, a.AppointmentTime ASC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/appointments', authMiddleware, async (req, res) => {
    const { petId, appointmentDate, appointmentTime, clinicName, vetName, reason, notes } = req.body;
    if (!petId || !appointmentDate)
        return res.status(400).json({ error: 'Hayvan ve tarih zorunludur.' });
    try {
        const p = await getPool();
        await p.request()
            .input('petId',           sql.Int,           sanitizeInt(petId))
            .input('appointmentDate', sql.Date,           appointmentDate)
            .input('appointmentTime', sql.NVarChar(10),   sanitizeStr(appointmentTime, 10))
            .input('clinicName',      sql.NVarChar(200),  sanitizeStr(clinicName, 200))
            .input('vetName',         sql.NVarChar(200),  sanitizeStr(vetName, 200))
            .input('reason',          sql.NVarChar(500),  sanitizeStr(reason, 500))
            .input('notes',           sql.NVarChar(1000), sanitizeStr(notes, 1000))
            .query(`INSERT INTO dbo.Appointments
                    (PetId,AppointmentDate,AppointmentTime,ClinicName,VetName,Reason,Status,Notes,CreatedAt)
                    VALUES (@petId,@appointmentDate,@appointmentTime,@clinicName,@vetName,@reason,'bekliyor',@notes,GETDATE())`);
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  HATIRLATICILАР  ═══════════════
══════════════════════════════════════════ */

app.get('/api/reminders', authMiddleware, async (req, res) => {
    try {
        const p = await getPool();
        const result = await p.request()
            .input('userId', sql.Int, req.user.id)
            .query(`SELECT r.*, pt.Name AS PetName
                    FROM dbo.Reminders r
                    INNER JOIN dbo.Pets pt ON r.PetId=pt.Id
                    WHERE pt.UserId=@userId AND r.IsCompleted=0
                    ORDER BY r.DueDate ASC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/reminders', authMiddleware, async (req, res) => {
    const { petId, reminderType, title, description, dueDate, isRecurring, recurrenceInterval } = req.body;
    if (!petId || !title || !dueDate)
        return res.status(400).json({ error: 'Hayvan, başlık ve tarih zorunludur.' });
    try {
        const p = await getPool();
        await p.request()
            .input('petId',              sql.Int,           sanitizeInt(petId))
            .input('reminderType',       sql.NVarChar(50),   sanitizeStr(reminderType, 50))
            .input('title',              sql.NVarChar(200),  sanitizeStr(title, 200))
            .input('description',        sql.NVarChar(1000), sanitizeStr(description, 1000))
            .input('dueDate',            sql.Date,           dueDate)
            .input('isRecurring',        sql.Bit,            isRecurring ? 1 : 0)
            .input('recurrenceInterval', sql.Int,            sanitizeInt(recurrenceInterval))
            .query(`INSERT INTO dbo.Reminders
                    (PetId,ReminderType,Title,Description,DueDate,IsRecurring,RecurrenceInterval,IsCompleted,CreatedAt)
                    VALUES (@petId,@reminderType,@title,@description,@dueDate,
                            @isRecurring,@recurrenceInterval,0,GETDATE())`);
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

// Hatırlatıcı tamamlandı olarak işaretle
app.patch('/api/reminders/:id/complete', authMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    try {
        const p = await getPool();
        await p.request()
            .input('id',     sql.Int, id)
            .input('userId', sql.Int, req.user.id)
            .query(`UPDATE dbo.Reminders SET IsCompleted=1
                    WHERE Id=@id AND PetId IN (SELECT Id FROM dbo.Pets WHERE UserId=@userId)`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Güncelleme hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  DASHBOARD ÖZET  ══════════════
══════════════════════════════════════════ */

app.get('/api/dashboard', authMiddleware, async (req, res) => {
    try {
        const p    = await getPool();
        const uid  = req.user.id;

        const [pets, upcoming_vax, upcoming_apt, reminders] = await Promise.all([
            p.request()
             .input('userId', sql.Int, uid)
             .query('SELECT * FROM dbo.Pets WHERE UserId=@userId AND IsActive=1'),
            p.request()
             .input('userId', sql.Int, uid)
             .query(`SELECT v.*, pt.Name AS PetName FROM dbo.Vaccinations v
                     INNER JOIN dbo.Pets pt ON v.PetId=pt.Id
                     WHERE pt.UserId=@userId AND v.NextDate BETWEEN GETDATE() AND DATEADD(day,30,GETDATE())
                     ORDER BY v.NextDate ASC`),
            p.request()
             .input('userId', sql.Int, uid)
             .query(`SELECT a.*, pt.Name AS PetName FROM dbo.Appointments a
                     INNER JOIN dbo.Pets pt ON a.PetId=pt.Id
                     WHERE pt.UserId=@userId AND a.AppointmentDate >= CAST(GETDATE() AS DATE)
                     ORDER BY a.AppointmentDate ASC`),
            p.request()
             .input('userId', sql.Int, uid)
             .query(`SELECT r.*, pt.Name AS PetName FROM dbo.Reminders r
                     INNER JOIN dbo.Pets pt ON r.PetId=pt.Id
                     WHERE pt.UserId=@userId AND r.IsCompleted=0 AND r.DueDate <= DATEADD(day,7,GETDATE())
                     ORDER BY r.DueDate ASC`),
        ]);

        res.json({
            pets:           pets.recordset,
            upcomingVax:    upcoming_vax.recordset,
            upcomingApt:    upcoming_apt.recordset,
            activeReminders: reminders.recordset,
        });
    } catch (err) {
        console.error('Dashboard hatası:', err.message);
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

/* ══════════════════════════════════════════
   SUNUCU BAŞLAT
══════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ PetMate sunucu çalışıyor: http://localhost:${PORT}`);
    console.log(`   Ortam: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;