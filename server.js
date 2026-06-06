

require('dotenv').config();

const express   = require('express');
const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');

const app = express();

app.use(helmet());
app.use(express.static('.'));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Çok fazla istek gönderildi. Lütfen 15 dakika bekleyin.',
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Çok fazla giriş denemesi. Lütfen 15 dakika bekleyin.',
});

app.use('/api/', apiLimiter);
app.use('/kullanici-giris', authLimiter);
app.use('/kullanici-kayit', authLimiter);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }  // Render için gerekli
        : false,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Veritabanı bağlantı hatası:', err.message);
    } else {
        console.log('✅ PostgreSQL bağlantısı başarılı');
        release();
    }
});

async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS kullanicilar (
                kullanici_id  SERIAL PRIMARY KEY,
                kullanici_adi VARCHAR(100) UNIQUE NOT NULL,
                sifre         VARCHAR(255) NOT NULL,
                email         VARCHAR(255),
                rol           VARCHAR(20) DEFAULT 'user',
                olusturulma   TIMESTAMP DEFAULT NOW()
            );

            DROP TABLE IF EXISTS hayvan_ilanlari CASCADE; CREATE TABLE hayvan_ilanlari (
                id          SERIAL PRIMARY KEY,
                ilan_turu   VARCHAR(50),
                hayvan_turu VARCHAR(50),
                hayvan_adi  VARCHAR(100),
                irk         VARCHAR(100),
                yas         INTEGER,
                cinsiyet    VARCHAR(20),
                renk        VARCHAR(100),
                sehir       VARCHAR(100),
                aciklama    TEXT,
                iletisim    VARCHAR(100),
                foto_url    TEXT,
                tarih       TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS one_cikan_ilanlar (
                id      SERIAL PRIMARY KEY,
                ilan_id INTEGER REFERENCES hayvan_ilanlari(id) ON DELETE CASCADE,
                sira    INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pets (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER REFERENCES kullanicilar(kullanici_id) ON DELETE CASCADE,
                name       VARCHAR(100) NOT NULL,
                species    VARCHAR(50)  NOT NULL,
                breed      VARCHAR(100),
                birth_date DATE,
                weight     NUMERIC(5,2),
                gender     VARCHAR(20),
                color      VARCHAR(100),
                photo_url  VARCHAR(500),
                notes      TEXT,
                is_active  BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS vaccinations (
                id           SERIAL PRIMARY KEY,
                pet_id       INTEGER REFERENCES pets(id) ON DELETE CASCADE,
                vaccine_name VARCHAR(200) NOT NULL,
                vaccine_date DATE NOT NULL,
                next_date    DATE,
                vet_name     VARCHAR(200),
                notes        TEXT,
                created_at   TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS medical_records (
                id           SERIAL PRIMARY KEY,
                pet_id       INTEGER REFERENCES pets(id) ON DELETE CASCADE,
                record_date  DATE NOT NULL,
                record_type  VARCHAR(100) NOT NULL,
                diagnosis    TEXT,
                treatment    TEXT,
                prescription TEXT,
                vet_name     VARCHAR(200),
                clinic_name  VARCHAR(200),
                cost         NUMERIC(10,2),
                notes        TEXT,
                created_at   TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS appointments (
                id               SERIAL PRIMARY KEY,
                pet_id           INTEGER REFERENCES pets(id) ON DELETE CASCADE,
                appointment_date DATE NOT NULL,
                appointment_time VARCHAR(10),
                clinic_name      VARCHAR(200),
                vet_name         VARCHAR(200),
                reason           VARCHAR(500),
                status           VARCHAR(50) DEFAULT 'bekliyor',
                notes            TEXT,
                created_at       TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS reminders (
                id                  SERIAL PRIMARY KEY,
                pet_id              INTEGER REFERENCES pets(id) ON DELETE CASCADE,
                reminder_type       VARCHAR(50),
                title               VARCHAR(200) NOT NULL,
                description         TEXT,
                due_date            DATE NOT NULL,
                is_recurring        BOOLEAN DEFAULT FALSE,
                recurrence_interval INTEGER,
                is_completed        BOOLEAN DEFAULT FALSE,
                created_at          TIMESTAMP DEFAULT NOW()
            );
        `);
        console.log('✅ Tablolar hazır');
    } catch (err) {
        console.error('❌ Tablo oluşturma hatası:', err.message);
    } finally {
        client.release();
    }
}

initDB();

const JWT_SECRET = process.env.JWT_SECRET || 'degistirmeniz_gereken_gizli_anahtar';

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Giriş yapmanız gerekiyor.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(403).json({ error: 'Oturum süresi dolmuş. Tekrar giriş yapın.' });
    }
}

function adminMiddleware(req, res, next) {
    if (!req.user || req.user.rol !== 'admin')
        return res.status(403).json({ error: 'Bu işlem için yetkiniz yok.' });
    next();
}

const sanitizeStr = (val, maxLen = 255) => {
    if (val === undefined || val === null) return null;
    return String(val).trim().substring(0, maxLen);
};

const sanitizeInt = (val) => {
    const n = parseInt(val);
    return isNaN(n) ? null : n;
};

const sanitizeFloat = (val) => {
    const n = parseFloat(val);
    return isNaN(n) ? null : n;
};

app.post('/ilan-ekle', async (req, res) => {
    if (!req.body || Object.keys(req.body).length === 0)
        return res.status(400).json({ error: 'Veri ulaşmıyor.' });
    try {
        await pool.query(
            `INSERT INTO hayvan_ilanlari
             (ilan_turu, hayvan_turu, hayvan_adi, irk, yas, cinsiyet, renk, sehir, aciklama, iletisim, foto_url)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
                sanitizeStr(req.body.ilanTuru, 50),
                sanitizeStr(req.body.hayvanTuru, 50),
                sanitizeStr(req.body.hayvanAdi, 100),
                sanitizeStr(req.body.irk, 100),
                sanitizeInt(req.body.yas),
                sanitizeStr(req.body.cinsiyet, 20),
                sanitizeStr(req.body.renk, 100),
                sanitizeStr(req.body.sehir, 100),
                sanitizeStr(req.body.aciklama, 2000),
                sanitizeStr(req.body.iletisim, 100),
                req.body.fotoUrl || null,
            ]
        );
        res.json({ success: true, message: 'İlan başarıyla kaydedildi.' });
    } catch (err) {
        console.error('Hata (ilan-ekle):', err.message);
        res.status(500).json({ error: 'Veritabanı hatası oluştu.' });
    }
});

app.get('/ilanlari-getir', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                id AS "Id",
                ilan_turu   AS "IlanTuru",
                hayvan_turu AS "HayvanTuru",
                hayvan_adi  AS "HayvanAdi",
                irk         AS "Irk",
                yas         AS "Yas",
                cinsiyet    AS "Cinsiyet",
                renk        AS "Renk",
                sehir       AS "Sehir",
                aciklama    AS "Aciklama",
                iletisim    AS "Iletisim",
                foto_url    AS "FotoUrl",
                tarih       AS "Tarih"
             FROM hayvan_ilanlari
             ORDER BY id DESC`
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Hata (ilanlari-getir):', err.message);
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.delete('/ilan-sil/:id', authMiddleware, adminMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Geçersiz ID.' });
    try {
        await pool.query('DELETE FROM hayvan_ilanlari WHERE id = $1', [id]);
        res.json({ success: true, message: 'İlan silindi.' });
    } catch (err) {
        console.error('Hata (ilan-sil):', err.message);
        res.status(500).json({ error: 'Silme hatası.' });
    }
});

app.get('/one-cikan-ilanlar', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                h.id AS "Id",
                h.ilan_turu   AS "IlanTuru",
                h.hayvan_turu AS "HayvanTuru",
                h.hayvan_adi  AS "HayvanAdi",
                h.irk         AS "Irk",
                h.yas         AS "Yas",
                h.cinsiyet    AS "Cinsiyet",
                h.renk        AS "Renk",
                h.sehir       AS "Sehir",
                h.aciklama    AS "Aciklama",
                h.iletisim    AS "Iletisim"
            FROM hayvan_ilanlari h
            INNER JOIN one_cikan_ilanlar o ON h.id = o.ilan_id
            ORDER BY o.sira ASC
        `);
        res.json(result.rows);
    } catch {
        res.json([]);
    }
});

app.post('/one-cikan-guncelle', authMiddleware, adminMiddleware, async (req, res) => {
    const { ilanIds } = req.body;
    if (!Array.isArray(ilanIds)) return res.status(400).json({ error: 'Geçersiz format.' });
    if (ilanIds.length > 6)     return res.status(400).json({ error: 'En fazla 6 ilan seçilebilir.' });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM one_cikan_ilanlar');
        for (let i = 0; i < ilanIds.length; i++) {
            const id = sanitizeInt(ilanIds[i]);
            if (!id) continue;
            await client.query(
                'INSERT INTO one_cikan_ilanlar (ilan_id, sira) VALUES ($1, $2)',
                [id, i + 1]
            );
        }
        await client.query('COMMIT');
        res.json({ success: true, message: 'Güncellendi.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Hata (one-cikan-guncelle):', err.message);
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.get('/one-cikan-idler', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT ilan_id FROM one_cikan_ilanlar ORDER BY sira ASC');
        res.json(result.rows.map(r => r.ilan_id));
    } catch {
        res.json([]);
    }
});

app.post('/kullanici-kayit', async (req, res) => {
    const { kullanici, sifre, email } = req.body;
    if (!kullanici || !sifre)
        return res.status(400).json({ error: 'Zorunlu alanlar eksik.' });
    if (kullanici.length < 3)
        return res.status(400).json({ error: 'Kullanıcı adı en az 3 karakter olmalı.' });
    if (sifre.length < 8)
        return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı.' });

    try {
        const kontrol = await pool.query(
            'SELECT COUNT(*) AS sayi FROM kullanicilar WHERE kullanici_adi = $1',
            [kullanici]
        );
        if (parseInt(kontrol.rows[0].sayi) > 0)
            return res.status(409).json({ error: 'Bu kullanıcı adı zaten alınmış.' });

        const hashedSifre = await bcrypt.hash(sifre, 12);
        await pool.query(
            `INSERT INTO kullanicilar (kullanici_adi, sifre, email, rol)
             VALUES ($1, $2, $3, 'user')`,
            [kullanici, hashedSifre, sanitizeStr(email)]
        );
        res.json({ success: true, message: 'Kayıt başarılı.' });
    } catch (err) {
        console.error('Hata (kullanici-kayit):', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// Giriş
app.post('/kullanici-giris', async (req, res) => {
    const { kullanici, sifre } = req.body;
    if (!kullanici || !sifre)
        return res.status(400).json({ error: 'Zorunlu alanlar eksik.' });
    try {
        const result = await pool.query(
            'SELECT kullanici_id, kullanici_adi, sifre, rol FROM kullanicilar WHERE kullanici_adi = $1',
            [kullanici]
        );
        if (!result.rows.length)
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });

        const user = result.rows[0];
        const sifreUyumu = await bcrypt.compare(sifre, user.sifre);
        if (!sifreUyumu)
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });

        const token = jwt.sign(
            { id: user.kullanici_id, kullanici: user.kullanici_adi, rol: user.rol },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ success: true, token, kullanici: user.kullanici_adi, rol: user.rol });
    } catch (err) {
        console.error('Hata (kullanici-giris):', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═════  PET MANAGEMENT  ══════════════════
══════════════════════════════════════════ */

// Hayvanları getir
app.get('/api/pets', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                id AS "Id", user_id AS "UserId", name AS "Name",
                species AS "Species", breed AS "Breed",
                birth_date AS "BirthDate", weight AS "Weight",
                gender AS "Gender", color AS "Color",
                photo_url AS "PhotoUrl", notes AS "Notes",
                is_active AS "IsActive", created_at AS "CreatedAt"
             FROM pets
             WHERE user_id = $1 AND is_active = TRUE
             ORDER BY created_at DESC`,
            [req.user.id]
        );
        res.json(result.rows);
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
        const result = await pool.query(
            `INSERT INTO pets
             (user_id, name, species, breed, birth_date, weight, gender, color, photo_url, notes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             RETURNING id`,
            [
                req.user.id,
                sanitizeStr(name, 100),
                sanitizeStr(species, 50),
                sanitizeStr(breed, 100),
                birthDate || null,
                sanitizeFloat(weight),
                sanitizeStr(gender, 20),
                sanitizeStr(color, 100),
                sanitizeStr(photoUrl, 500),
                sanitizeStr(notes, 2000),
            ]
        );
        res.status(201).json({ success: true, id: result.rows[0].id });
    } catch (err) {
        console.error('Hata (pets POST):', err.message);
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

// Hayvan güncelle
app.put('/api/pets/:id', authMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Geçersiz ID.' });
    const { name, species, breed, birthDate, weight, gender, color, photoUrl, notes } = req.body;
    try {
        await pool.query(
            `UPDATE pets
             SET name=$1, species=$2, breed=$3, birth_date=$4,
                 weight=$5, gender=$6, color=$7, photo_url=$8, notes=$9
             WHERE id=$10 AND user_id=$11`,
            [
                sanitizeStr(name, 100), sanitizeStr(species, 50),
                sanitizeStr(breed, 100), birthDate || null,
                sanitizeFloat(weight), sanitizeStr(gender, 20),
                sanitizeStr(color, 100), sanitizeStr(photoUrl, 500),
                sanitizeStr(notes, 2000), id, req.user.id,
            ]
        );
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
        await pool.query(
            'UPDATE pets SET is_active = FALSE WHERE id = $1 AND user_id = $2',
            [id, req.user.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Silme hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  AŞI TAKİBİ  ════════════════════
══════════════════════════════════════════ */

app.get('/api/pets/:petId/vaccinations', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    try {
        const result = await pool.query(
            `SELECT v.id AS "Id", v.pet_id AS "PetId",
                    v.vaccine_name AS "VaccineName", v.vaccine_date AS "VaccineDate",
                    v.next_date AS "NextDate", v.vet_name AS "VetName",
                    v.notes AS "Notes", v.created_at AS "CreatedAt"
             FROM vaccinations v
             INNER JOIN pets p ON v.pet_id = p.id
             WHERE v.pet_id = $1 AND p.user_id = $2
             ORDER BY v.vaccine_date DESC`,
            [petId, req.user.id]
        );
        res.json(result.rows);
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
        await pool.query(
            `INSERT INTO vaccinations (pet_id, vaccine_name, vaccine_date, next_date, vet_name, notes)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [
                petId,
                sanitizeStr(vaccineName, 200),
                vaccineDate,
                nextDate || null,
                sanitizeStr(vetName, 200),
                sanitizeStr(notes, 1000),
            ]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  SAĞLIK KAYITLARI  ══════════════
══════════════════════════════════════════ */

app.get('/api/pets/:petId/medical', authMiddleware, async (req, res) => {
    const petId = sanitizeInt(req.params.petId);
    try {
        const result = await pool.query(
            `SELECT m.*
             FROM medical_records m
             INNER JOIN pets p ON m.pet_id = p.id
             WHERE m.pet_id = $1 AND p.user_id = $2
             ORDER BY m.record_date DESC`,
            [petId, req.user.id]
        );
        res.json(result.rows);
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
        await pool.query(
            `INSERT INTO medical_records
             (pet_id, record_date, record_type, diagnosis, treatment, prescription, vet_name, clinic_name, cost, notes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [
                petId, recordDate,
                sanitizeStr(recordType, 100),
                sanitizeStr(diagnosis, 1000),
                sanitizeStr(treatment, 1000),
                sanitizeStr(prescription, 1000),
                sanitizeStr(vetName, 200),
                sanitizeStr(clinicName, 200),
                sanitizeFloat(cost),
                sanitizeStr(notes, 2000),
            ]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  RANDEVULAR  ════════════════════
══════════════════════════════════════════ */

app.get('/api/appointments', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                a.id AS "Id", a.pet_id AS "PetId",
                a.appointment_date AS "AppointmentDate",
                a.appointment_time AS "AppointmentTime",
                a.clinic_name AS "ClinicName", a.vet_name AS "VetName",
                a.reason AS "Reason", a.status AS "Status",
                a.notes AS "Notes",
                p.name AS "PetName", p.species AS "PetSpecies"
             FROM appointments a
             INNER JOIN pets p ON a.pet_id = p.id
             WHERE p.user_id = $1 AND a.appointment_date >= CURRENT_DATE
             ORDER BY a.appointment_date ASC, a.appointment_time ASC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/appointments', authMiddleware, async (req, res) => {
    const { petId, appointmentDate, appointmentTime, clinicName, vetName, reason, notes } = req.body;
    if (!petId || !appointmentDate)
        return res.status(400).json({ error: 'Hayvan ve tarih zorunludur.' });
    try {
        await pool.query(
            `INSERT INTO appointments
             (pet_id, appointment_date, appointment_time, clinic_name, vet_name, reason, status, notes)
             VALUES ($1,$2,$3,$4,$5,$6,'bekliyor',$7)`,
            [
                sanitizeInt(petId), appointmentDate,
                sanitizeStr(appointmentTime, 10),
                sanitizeStr(clinicName, 200),
                sanitizeStr(vetName, 200),
                sanitizeStr(reason, 500),
                sanitizeStr(notes, 1000),
            ]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  HATIRLATICILАР  ════════════════
══════════════════════════════════════════ */

app.get('/api/reminders', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                r.id AS "Id", r.pet_id AS "PetId",
                r.reminder_type AS "ReminderType", r.title AS "Title",
                r.description AS "Description", r.due_date AS "DueDate",
                r.is_recurring AS "IsRecurring",
                r.recurrence_interval AS "RecurrenceInterval",
                r.is_completed AS "IsCompleted",
                p.name AS "PetName"
             FROM reminders r
             INNER JOIN pets p ON r.pet_id = p.id
             WHERE p.user_id = $1 AND r.is_completed = FALSE
             ORDER BY r.due_date ASC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Veri çekme hatası.' });
    }
});

app.post('/api/reminders', authMiddleware, async (req, res) => {
    const { petId, reminderType, title, description, dueDate, isRecurring, recurrenceInterval } = req.body;
    if (!petId || !title || !dueDate)
        return res.status(400).json({ error: 'Hayvan, başlık ve tarih zorunludur.' });
    try {
        await pool.query(
            `INSERT INTO reminders
             (pet_id, reminder_type, title, description, due_date, is_recurring, recurrence_interval)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [
                sanitizeInt(petId),
                sanitizeStr(reminderType, 50),
                sanitizeStr(title, 200),
                sanitizeStr(description, 1000),
                dueDate,
                isRecurring ? true : false,
                sanitizeInt(recurrenceInterval),
            ]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Kayıt hatası.' });
    }
});

// Hatırlatıcı tamamlandı
app.patch('/api/reminders/:id/complete', authMiddleware, async (req, res) => {
    const id = sanitizeInt(req.params.id);
    try {
        await pool.query(
            `UPDATE reminders SET is_completed = TRUE
             WHERE id = $1
               AND pet_id IN (SELECT id FROM pets WHERE user_id = $2)`,
            [id, req.user.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Güncelleme hatası.' });
    }
});

/* ══════════════════════════════════════════
   ═══════  DASHBOARD ÖZET  ════════════════
══════════════════════════════════════════ */

app.get('/api/dashboard', authMiddleware, async (req, res) => {
    const uid = req.user.id;
    try {
        const [pets, vax, apt, rem] = await Promise.all([
            pool.query(
                `SELECT id AS "Id", name AS "Name", species AS "Species",
                        breed AS "Breed", birth_date AS "BirthDate",
                        weight AS "Weight", gender AS "Gender",
                        color AS "Color", photo_url AS "PhotoUrl", notes AS "Notes"
                 FROM pets WHERE user_id = $1 AND is_active = TRUE`,
                [uid]
            ),
            pool.query(
                `SELECT v.id AS "Id", v.vaccine_name AS "VaccineName",
                        v.vaccine_date AS "VaccineDate", v.next_date AS "NextDate",
                        v.vet_name AS "VetName", p.name AS "PetName"
                 FROM vaccinations v
                 INNER JOIN pets p ON v.pet_id = p.id
                 WHERE p.user_id = $1
                   AND v.next_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '30 days'
                 ORDER BY v.next_date ASC`,
                [uid]
            ),
            pool.query(
                `SELECT a.id AS "Id", a.appointment_date AS "AppointmentDate",
                        a.appointment_time AS "AppointmentTime",
                        a.clinic_name AS "ClinicName", a.vet_name AS "VetName",
                        a.reason AS "Reason", a.status AS "Status",
                        p.name AS "PetName"
                 FROM appointments a
                 INNER JOIN pets p ON a.pet_id = p.id
                 WHERE p.user_id = $1 AND a.appointment_date >= CURRENT_DATE
                 ORDER BY a.appointment_date ASC`,
                [uid]
            ),
            pool.query(
                `SELECT r.id AS "Id", r.reminder_type AS "ReminderType",
                        r.title AS "Title", r.due_date AS "DueDate",
                        r.is_recurring AS "IsRecurring", p.name AS "PetName"
                 FROM reminders r
                 INNER JOIN pets p ON r.pet_id = p.id
                 WHERE p.user_id = $1
                   AND r.is_completed = FALSE
                   AND r.due_date <= CURRENT_DATE + INTERVAL '7 days'
                 ORDER BY r.due_date ASC`,
                [uid]
            ),
        ]);

        res.json({
            pets:            pets.rows,
            upcomingVax:     vax.rows,
            upcomingApt:     apt.rows,
            activeReminders: rem.rows,
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
