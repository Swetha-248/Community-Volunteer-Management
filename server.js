/**
 * VolunteerHub Backend API
 * Node.js + Express REST API
 * 
 * Install: npm install express bcryptjs jsonwebtoken cors multer uuid
 * Run: node server.js
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'volunteerhub-secret-key-change-in-prod';

// ─── MIDDLEWARE ──────────────────────────────────────────────
app.use(cors({ origin: ['http://localhost:3000', 'http://127.0.0.1:5500'] }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Multer: File uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = `uploads/${req.user?.id || 'temp'}`;
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// ─── IN-MEMORY DB (replace with real DB in production) ───────
const DB = {
  volunteers: [],    // { id, firstName, lastName, email, passwordHash, phone, location, bio, skills[], experience, availability, rating, eventsCompleted, documents[], createdAt }
  organizations: [], // { id, name, email, passwordHash, phone, type, description, location, createdAt }
  events: [],        // { id, orgId, title, category, description, date, time, location, skills[], volunteersNeeded, status: 'open'|'closed', createdAt }
  applications: [],  // { id, eventId, volunteerId, status: 'pending'|'selected'|'rejected', message, experience, appliedAt }
  ratings: [],       // { id, eventId, volunteerId, orgId, score, comment, createdAt }
};

// Seed with demo data
seedDemoData();

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────
function auth(requiredRole) {
  return (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: 'Forbidden: wrong role' });
      }
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ─── HELPER ──────────────────────────────────────────────────
function omit(obj, keys) {
  return Object.fromEntries(Object.entries(obj).filter(([k]) => !keys.includes(k)));
}

function calcMatchScore(volunteer, event) {
  // Skill match
  const matchedSkills = (volunteer.skills || []).filter(s => (event.skills || []).includes(s));
  const skillScore = event.skills?.length
    ? Math.round((matchedSkills.length / event.skills.length) * 70)
    : 50;

  // Experience score (0-20)
  const expMap = { 'Less than 1 year': 5, '1–3 years': 12, '3–5 years': 17, '5+ years': 20 };
  const expScore = expMap[volunteer.experience] || 5;

  // Rating score (0-10)
  const ratingScore = Math.round(((volunteer.rating || 0) / 5) * 10);

  return Math.min(100, skillScore + expScore + ratingScore);
}

// ─── AUTH ROUTES ─────────────────────────────────────────────

// POST /api/auth/register/volunteer
app.post('/api/auth/register/volunteer', async (req, res) => {
  const { firstName, lastName, email, password, phone, location } = req.body;

  if (!firstName || !email || !password)
    return res.status(400).json({ error: 'firstName, email, and password are required' });

  if (DB.volunteers.find(v => v.email === email))
    return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 12);
  const volunteer = {
    id: uuidv4(), firstName, lastName, email, passwordHash,
    phone: phone || '', location: location || '',
    bio: '', skills: [], experience: 'Less than 1 year',
    availability: 'Weekends Only', rating: 0, eventsCompleted: 0,
    documents: [], role: 'volunteer', createdAt: new Date().toISOString()
  };
  DB.volunteers.push(volunteer);

  const token = jwt.sign({ id: volunteer.id, role: 'volunteer', email }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: omit(volunteer, ['passwordHash']) });
});

// POST /api/auth/register/org
app.post('/api/auth/register/org', async (req, res) => {
  const { name, email, password, phone, type, description, location } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: 'name, email, and password are required' });

  if (DB.organizations.find(o => o.email === email))
    return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 12);
  const org = {
    id: uuidv4(), name, email, passwordHash,
    phone: phone || '', type: type || 'NGO / Non-Profit',
    description: description || '', location: location || '',
    role: 'org', createdAt: new Date().toISOString()
  };
  DB.organizations.push(org);

  const token = jwt.sign({ id: org.id, role: 'org', email }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: omit(org, ['passwordHash']) });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role)
    return res.status(400).json({ error: 'email, password, and role required' });

  const db = role === 'org' ? DB.organizations : DB.volunteers;
  const user = db.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, role: user.role || role, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: omit(user, ['passwordHash']) });
});

// ─── VOLUNTEER ROUTES ─────────────────────────────────────────

// GET /api/volunteers/me
app.get('/api/volunteers/me', auth('volunteer'), (req, res) => {
  const vol = DB.volunteers.find(v => v.id === req.user.id);
  if (!vol) return res.status(404).json({ error: 'Not found' });
  res.json(omit(vol, ['passwordHash']));
});

// PUT /api/volunteers/me
app.put('/api/volunteers/me', auth('volunteer'), (req, res) => {
  const idx = DB.volunteers.findIndex(v => v.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const allowed = ['firstName', 'lastName', 'phone', 'location', 'bio', 'skills', 'experience', 'availability'];
  allowed.forEach(field => {
    if (req.body[field] !== undefined) DB.volunteers[idx][field] = req.body[field];
  });

  res.json(omit(DB.volunteers[idx], ['passwordHash']));
});

// POST /api/volunteers/me/documents
app.post('/api/volunteers/me/documents', auth('volunteer'), upload.array('files', 5), (req, res) => {
  const idx = DB.volunteers.findIndex(v => v.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const docs = req.files.map(f => ({
    id: uuidv4(), name: f.originalname, path: f.path,
    size: f.size, uploadedAt: new Date().toISOString()
  }));
  DB.volunteers[idx].documents.push(...docs);

  res.status(201).json({ documents: DB.volunteers[idx].documents });
});

// GET /api/volunteers/me/applications
app.get('/api/volunteers/me/applications', auth('volunteer'), (req, res) => {
  const apps = DB.applications.filter(a => a.volunteerId === req.user.id);
  const enriched = apps.map(a => ({
    ...a,
    event: DB.events.find(e => e.id === a.eventId) || null
  }));
  res.json(enriched);
});

// GET /api/volunteers/me/history
app.get('/api/volunteers/me/history', auth('volunteer'), (req, res) => {
  const completed = DB.applications.filter(a => a.volunteerId === req.user.id && a.status === 'selected');
  const enriched = completed.map(a => ({
    ...a,
    event: DB.events.find(e => e.id === a.eventId),
    rating: DB.ratings.find(r => r.volunteerId === req.user.id && r.eventId === a.eventId) || null
  }));
  res.json(enriched);
});

// ─── EVENT ROUTES ─────────────────────────────────────────────

// GET /api/events  (public, with filters)
app.get('/api/events', (req, res) => {
  const { category, skills, search, availability, page = 1, limit = 20 } = req.query;
  let events = DB.events.filter(e => e.status === 'open');

  if (category) events = events.filter(e => e.category === category);
  if (skills) {
    const skillArr = skills.split(',');
    events = events.filter(e => skillArr.some(s => e.skills.includes(s)));
  }
  if (search) {
    const q = search.toLowerCase();
    events = events.filter(e =>
      e.title.toLowerCase().includes(q) ||
      e.location.toLowerCase().includes(q) ||
      e.description.toLowerCase().includes(q)
    );
  }

  // Pagination
  const total = events.length;
  const start = (page - 1) * limit;
  events = events.slice(start, start + parseInt(limit));

  // Enrich with org name
  const enriched = events.map(e => ({
    ...e,
    orgName: DB.organizations.find(o => o.id === e.orgId)?.name || 'Unknown',
    applicantsCount: DB.applications.filter(a => a.eventId === e.id).length
  }));

  res.json({ events: enriched, total, page: parseInt(page), totalPages: Math.ceil(total / limit) });
});

// GET /api/events/:id
app.get('/api/events/:id', (req, res) => {
  const ev = DB.events.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Event not found' });

  const org = DB.organizations.find(o => o.id === ev.orgId);
  res.json({
    ...ev,
    orgName: org?.name,
    applicantsCount: DB.applications.filter(a => a.eventId === ev.id).length
  });
});

// POST /api/events  (org only)
app.post('/api/events', auth('org'), (req, res) => {
  const { title, category, description, date, time, location, skills, volunteersNeeded } = req.body;
  if (!title || !date || !location)
    return res.status(400).json({ error: 'title, date, and location are required' });

  const ev = {
    id: uuidv4(), orgId: req.user.id,
    title, category: category || 'community', description: description || '',
    date, time: time || '09:00', location,
    skills: skills || [], volunteersNeeded: volunteersNeeded || 10,
    status: 'open', createdAt: new Date().toISOString()
  };
  DB.events.push(ev);
  res.status(201).json(ev);
});

// PUT /api/events/:id  (org only, must own it)
app.put('/api/events/:id', auth('org'), (req, res) => {
  const idx = DB.events.findIndex(e => e.id === req.params.id && e.orgId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Event not found or not authorized' });

  const allowed = ['title', 'category', 'description', 'date', 'time', 'location', 'skills', 'volunteersNeeded', 'status'];
  allowed.forEach(f => { if (req.body[f] !== undefined) DB.events[idx][f] = req.body[f]; });

  res.json(DB.events[idx]);
});

// DELETE /api/events/:id  (org only)
app.delete('/api/events/:id', auth('org'), (req, res) => {
  const idx = DB.events.findIndex(e => e.id === req.params.id && e.orgId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found or not authorized' });
  DB.events.splice(idx, 1);
  res.json({ message: 'Event deleted' });
});

// GET /api/events/org/mine  (org's own events)
app.get('/api/events/org/mine', auth('org'), (req, res) => {
  const events = DB.events.filter(e => e.orgId === req.user.id);
  const enriched = events.map(e => ({
    ...e,
    applicantsCount: DB.applications.filter(a => a.eventId === e.id).length,
    selectedCount: DB.applications.filter(a => a.eventId === e.id && a.status === 'selected').length,
  }));
  res.json(enriched);
});

// ─── APPLICATION ROUTES ───────────────────────────────────────

// POST /api/events/:id/apply  (volunteer)
app.post('/api/events/:id/apply', auth('volunteer'), (req, res) => {
  const ev = DB.events.find(e => e.id === req.params.id && e.status === 'open');
  if (!ev) return res.status(404).json({ error: 'Event not found or closed' });

  const alreadyApplied = DB.applications.find(a => a.eventId === ev.id && a.volunteerId === req.user.id);
  if (alreadyApplied) return res.status(409).json({ error: 'Already applied to this event' });

  const app_ = {
    id: uuidv4(), eventId: ev.id, volunteerId: req.user.id,
    status: 'pending',
    message: req.body.message || '',
    experience: req.body.experience || '',
    appliedAt: new Date().toISOString()
  };
  DB.applications.push(app_);
  res.status(201).json(app_);
});

// GET /api/events/:id/applicants  (org only, must own event)
app.get('/api/events/:id/applicants', auth('org'), (req, res) => {
  const ev = DB.events.find(e => e.id === req.params.id && e.orgId === req.user.id);
  if (!ev) return res.status(404).json({ error: 'Event not found or not authorized' });

  const { sortBy } = req.query;
  let apps = DB.applications.filter(a => a.eventId === ev.id);

  const enriched = apps.map(a => {
    const vol = DB.volunteers.find(v => v.id === a.volunteerId);
    if (!vol) return null;
    return {
      ...a,
      volunteer: omit(vol, ['passwordHash', 'documents']),
      matchScore: calcMatchScore(vol, ev)
    };
  }).filter(Boolean);

  // Sort
  if (sortBy === 'match') enriched.sort((a, b) => b.matchScore - a.matchScore);
  else if (sortBy === 'experience') enriched.sort((a, b) => b.volunteer.eventsCompleted - a.volunteer.eventsCompleted);
  else if (sortBy === 'rating') enriched.sort((a, b) => b.volunteer.rating - a.volunteer.rating);

  res.json(enriched);
});

// PATCH /api/applications/:id/status  (org selects/rejects)
app.patch('/api/applications/:id/status', auth('org'), (req, res) => {
  const { status } = req.body;
  if (!['selected', 'rejected'].includes(status))
    return res.status(400).json({ error: 'status must be selected or rejected' });

  const appIdx = DB.applications.findIndex(a => a.id === req.params.id);
  if (appIdx === -1) return res.status(404).json({ error: 'Application not found' });

  const ev = DB.events.find(e => e.id === DB.applications[appIdx].eventId && e.orgId === req.user.id);
  if (!ev) return res.status(403).json({ error: 'Not authorized' });

  DB.applications[appIdx].status = status;
  DB.applications[appIdx].updatedAt = new Date().toISOString();

  // In production: send email notification here
  console.log(`📧 Notification queued: volunteer ${DB.applications[appIdx].volunteerId} ${status} for event ${ev.title}`);

  res.json(DB.applications[appIdx]);
});

// ─── RATINGS ROUTES ───────────────────────────────────────────

// POST /api/ratings  (org rates volunteer after event)
app.post('/api/ratings', auth('org'), (req, res) => {
  const { volunteerId, eventId, score, comment } = req.body;
  if (!volunteerId || !eventId || !score)
    return res.status(400).json({ error: 'volunteerId, eventId, and score required' });
  if (score < 1 || score > 5)
    return res.status(400).json({ error: 'score must be 1-5' });

  const existing = DB.ratings.find(r => r.volunteerId === volunteerId && r.eventId === eventId);
  if (existing) return res.status(409).json({ error: 'Already rated this volunteer for this event' });

  const rating = {
    id: uuidv4(), orgId: req.user.id, volunteerId, eventId,
    score, comment: comment || '', createdAt: new Date().toISOString()
  };
  DB.ratings.push(rating);

  // Recalculate volunteer avg rating
  const volRatings = DB.ratings.filter(r => r.volunteerId === volunteerId);
  const avgRating = volRatings.reduce((sum, r) => sum + r.score, 0) / volRatings.length;
  const volIdx = DB.volunteers.findIndex(v => v.id === volunteerId);
  if (volIdx !== -1) {
    DB.volunteers[volIdx].rating = Math.round(avgRating * 10) / 10;
    DB.volunteers[volIdx].eventsCompleted = volRatings.length;
  }

  res.status(201).json(rating);
});

// ─── SEARCH/MATCH ROUTE ───────────────────────────────────────

// GET /api/volunteers/search  (org searches volunteers)
app.get('/api/volunteers/search', auth('org'), (req, res) => {
  const { skills, location, experience, minRating } = req.query;
  let results = DB.volunteers;

  if (skills) {
    const skillArr = skills.split(',');
    results = results.filter(v => skillArr.some(s => v.skills.includes(s)));
  }
  if (location) {
    const loc = location.toLowerCase();
    results = results.filter(v => v.location.toLowerCase().includes(loc));
  }
  if (experience) {
    results = results.filter(v => v.experience === experience);
  }
  if (minRating) {
    results = results.filter(v => v.rating >= parseFloat(minRating));
  }

  res.json(results.map(v => omit(v, ['passwordHash', 'documents'])));
});

// ─── HEALTH CHECK ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), dbCounts: {
    volunteers: DB.volunteers.length,
    organizations: DB.organizations.length,
    events: DB.events.length,
    applications: DB.applications.length,
  }});
});

// ─── SEED DEMO DATA ───────────────────────────────────────────
async function seedDemoData() {
  const hash = await bcrypt.hash('password123', 12);

  DB.organizations.push({
    id: 'org-demo-1', name: 'Green Earth Organization',
    email: 'org@demo.com', passwordHash: hash,
    phone: '+91 9000000001', type: 'NGO / Non-Profit',
    description: 'Dedicated to environmental conservation.',
    location: 'Chennai, Tamil Nadu', role: 'org',
    createdAt: new Date().toISOString()
  });

  DB.volunteers.push({
    id: 'vol-demo-1', firstName: 'John', lastName: 'Smith',
    email: 'volunteer@demo.com', passwordHash: hash,
    phone: '+91 9876543210', location: 'Chennai, Tamil Nadu',
    bio: 'Passionate community volunteer.',
    skills: ['teaching', 'coding', 'management'],
    experience: '1–3 years', availability: 'Weekends Only',
    rating: 4.8, eventsCompleted: 8, documents: [], role: 'volunteer',
    createdAt: new Date().toISOString()
  });

  const eventData = [
    { title: 'Beach Cleanup Drive', category: 'environment', date: '2025-04-12', time: '08:00', location: 'Marina Beach, Chennai', skills: ['management', 'driving'], volunteersNeeded: 30 },
    { title: 'Free Medical Camp', category: 'health', date: '2025-04-20', time: '09:00', location: 'Royapuram Community Center', skills: ['medical', 'management'], volunteersNeeded: 15 },
    { title: 'Digital Literacy Workshop', category: 'education', date: '2025-05-05', time: '10:00', location: 'Govt School, Tambaram', skills: ['coding', 'teaching'], volunteersNeeded: 10 },
  ];

  eventData.forEach(ed => {
    DB.events.push({
      id: uuidv4(), orgId: 'org-demo-1',
      description: `Join us for ${ed.title}. Make a real difference in the community.`,
      status: 'open', createdAt: new Date().toISOString(), ...ed
    });
  });

  console.log('✅ Demo data seeded. Login: volunteer@demo.com or org@demo.com (password: password123)');
}

// ─── START ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🌿 VolunteerHub API running on http://localhost:${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health\n`);
});

module.exports = app;
