/*
Single-file Social Media App (Full-stack) - Node.js + Express + MongoDB + React (via CDN)
Filename: social_single_file_app.js

Features:
- User registration & login (JWT)
- Create posts with optional image upload (Multer, local storage for demo)
- Edit / delete posts (ownership enforced)
- Like / unlike posts
- Comments on posts
- Simple feed (most recent posts first)
- Frontend: Single-page React app (served by Express) using CDN builds

Notes & Production Recommendations:
- This demo stores uploaded images on the server filesystem in /uploads. For production, use S3 (or similar) and serve via CDN.
- Use HTTPS in production and set a strong JWT_SECRET and secure cookie options if switching to cookie-based auth.
- Consider rate limiting, input validation (e.g., express-validator), and sanitization to prevent XSS.

Run instructions (local dev):
1. Save as `social_single_file_app.js`.
2. Install dependencies:
   npm init -y
   npm install express mongoose bcryptjs jsonwebtoken cors body-parser multer

3. Start MongoDB locally or set MONGODB_URI to your MongoDB connection string.
4. (Optional) Set JWT_SECRET env var:
   export JWT_SECRET="a_strong_secret"
5. Run:
   node social_single_file_app.js
6. Open http://localhost:3000

AWS Deployment notes (short):
- For simple deploy: push to EC2 and run with PM2 or systemd, set environment vars, open ports, use Nginx as reverse proxy, configure SSL.
- For managed deploy: create a Dockerfile and deploy to Elastic Beanstalk (Docker) or ECS with an Application Load Balancer.
- Move images to S3 and set CORS to allow your frontend domain.

*/

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/social_app';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

// Ensure uploads folder exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if(!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Multer: store files locally (demo). In production use S3 or similar.
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, UPLOAD_DIR); },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const name = Date.now() + '-' + Math.random().toString(36).slice(2,8) + ext;
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB limit

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// ----- MongoDB setup -----
mongoose.set('strictQuery', false);
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => { console.error('MongoDB connection error:', err.message); process.exit(1); });

// ----- Schemas -----
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  displayName: { type: String }
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
  text: { type: String },
  imageUrl: { type: String }, // relative URL like /uploads/xxxx
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', commentSchema);

// ----- Auth helpers -----
function generateToken(user){
  return jwt.sign({ id: user._id, username: user.username, displayName: user.displayName }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error: 'No authorization header' });
  const parts = auth.split(' ');
  if(parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid authorization format' });
  const token = parts[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(payload.id).select('-passwordHash');
    if(!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  }catch(err){ return res.status(401).json({ error: 'Invalid token' }); }
}

// ----- Routes: Auth -----
app.post('/api/auth/register', async (req, res) => {
  try{
    const { username, password, displayName } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'username and password required' });
    const existing = await User.findOne({ username });
    if(existing) return res.status(400).json({ error: 'username already taken' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ username, passwordHash: hash, displayName: displayName || username });
    await user.save();
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, username: user.username, displayName: user.displayName } });
  }catch(err){ console.error(err); res.status(500).json({ error: 'registration failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try{
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'username and password required' });
    const user = await User.findOne({ username });
    if(!user) return res.status(400).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({ error: 'invalid credentials' });
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, username: user.username, displayName: user.displayName } });
  }catch(err){ console.error(err); res.status(500).json({ error: 'login failed' }); }
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: { id: req.user._id, username: req.user.username, displayName: req.user.displayName } });
});

// ----- Routes: Posts -----
// Get feed (paginated)
app.get('/api/posts', async (req, res) => {
  try{
    const page = Math.max(0, parseInt(req.query.page || '0'));
    const limit = Math.min(50, parseInt(req.query.limit || '10'));
    const posts = await Post.find().sort({ createdAt: -1 }).skip(page * limit).limit(limit).populate('author', 'username displayName').lean();
    // add likeCount and likedByMe if token provided
    res.json(posts);
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to fetch posts' }); }
});

// Create post (supports optional image)
app.post('/api/posts', authMiddleware, upload.single('image'), async (req, res) => {
  try{
    const { text } = req.body;
    const imageUrl = req.file ? (`/uploads/${req.file.filename}`) : undefined;
    if(!text && !imageUrl) return res.status(400).json({ error: 'post must have text or image' });
    const post = new Post({ text, imageUrl, author: req.user._id });
    await post.save();
    const populated = await Post.findById(post._id).populate('author', 'username displayName');
    res.status(201).json(populated);
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to create post' }); }
});

// Edit post
app.put('/api/posts/:id', authMiddleware, upload.single('image'), async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    if(!post.author.equals(req.user._id)) return res.status(403).json({ error: 'not authorized' });
    const { text } = req.body;
    if(text !== undefined) post.text = text;
    if(req.file){
      // remove old image file if exists
      if(post.imageUrl){
        const oldPath = path.join(__dirname, post.imageUrl);
        fs.unlink(oldPath, () => {});
      }
      post.imageUrl = `/uploads/${req.file.filename}`;
    }
    await post.save();
    const populated = await Post.findById(post._id).populate('author', 'username displayName');
    res.json(populated);
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to update post' }); }
});

// Delete post
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    if(!post.author.equals(req.user._id)) return res.status(403).json({ error: 'not authorized' });
    if(post.imageUrl){ const imgPath = path.join(__dirname, post.imageUrl); fs.unlink(imgPath, () => {}); }
    await Comment.deleteMany({ post: post._id });
    await post.deleteOne();
    res.json({ success: true });
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to delete post' }); }
});

// ----- Likes -----
app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    const exists = post.likes.some(l => l.equals(req.user._id));
    if(!exists) post.likes.push(req.user._id);
    await post.save();
    res.json({ success: true, likeCount: post.likes.length });
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to like' }); }
});

app.post('/api/posts/:id/unlike', authMiddleware, async (req, res) => {
  try{
    const { id } = req.params;
    const post = await Post.findById(id);
    if(!post) return res.status(404).json({ error: 'post not found' });
    post.likes = post.likes.filter(l => !l.equals(req.user._id));
    await post.save();
    res.json({ success: true, likeCount: post.likes.length });
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to unlike' }); }
});

// ----- Comments -----
app.get('/api/posts/:postId/comments', async (req, res) => {
  try{
    const { postId } = req.params;
    const comments = await Comment.find({ post: postId }).sort({ createdAt: 1 }).populate('author', 'username displayName');
    res.json(comments);
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to fetch comments' }); }
});

app.post('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  try{
    const { postId } = req.params;
    const { text } = req.body;
    if(!text) return res.status(400).json({ error: 'text required' });
    const post = await Post.findById(postId);
    if(!post) return res.status(404).json({ error: 'post not found' });
    const comment = new Comment({ post: post._id, author: req.user._id, text });
    await comment.save();
    const populated = await Comment.findById(comment._id).populate('author', 'username displayName');
    res.status(201).json(populated);
  }catch(err){ console.error(err); res.status(500).json({ error: 'failed to add comment' }); }
});

// Simple health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ----- Frontend: React SPA via CDN (simple UI) -----
app.get('/', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Social Mini - Single File</title>
    <style>
      body { font-family: Arial, sans-serif; margin:0; padding:0; background:#f3f4f6; }
      .container { max-width:900px; margin:24px auto; background:white; padding:18px; border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,0.06); }
      header { display:flex; justify-content:space-between; align-items:center; }
      h1 { margin:0; }
      .flex { display:flex; gap:8px; align-items:center; }
      .feed { margin-top:12px; }
      .post { border:1px solid #eee; padding:12px; border-radius:8px; margin-bottom:12px; }
      img.post-img { max-width:100%; border-radius:6px; margin-top:8px; }
      .small { font-size:13px; color:#666 }
      .btn { padding:6px 10px; border-radius:6px; border:none; cursor:pointer; }
      .btn.primary { background:#2563eb; color:white; }
      .btn.ghost { background:transparent; border:1px solid #ddd; }
      input[type=text], textarea { padding:8px; border-radius:6px; border:1px solid #ddd; }
      .form-row { margin-bottom:8px; }
    </style>
  </head>
  <body>
    <div id="root" class="container"></div>

    <script src="https://unpkg.com/react@18/umd/react.development.js" crossorigin></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js" crossorigin></script>
    <script src="https://unpkg.com/babel-standalone@6.26.0/babel.min.js"></script>

    <script type="text/babel">
      const { useState, useEffect, useRef } = React;

      function api(path, method='GET', body=null, token=null, isForm=false){
        const opts = { method, headers: {} };
        if(body && !isForm){ opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
        if(body && isForm){ opts.body = body; }
        if(token) opts.headers['Authorization'] = 'Bearer '+token;
        return fetch(path, opts).then(r => r.json());
      }

      function App(){
        const [token, setToken] = useState(localStorage.getItem('token'));
        const [me, setMe] = useState(null);
        const [posts, setPosts] = useState([]);
        const [loading, setLoading] = useState(false);

        useEffect(()=>{ loadPosts(); if(token) loadMe(); }, [token]);

        async function loadMe(){ const res = await api('/api/me', 'GET', null, token); if(res.user) setMe(res.user); else { setToken(null); localStorage.removeItem('token'); } }
        async function loadPosts(){ setLoading(true); const data = await api('/api/posts'); setPosts(data || []); setLoading(false); }

        function onLogin(token, user){ setToken(token); localStorage.setItem('token', token); setMe(user); }
        function onLogout(){ setToken(null); localStorage.removeItem('token'); setMe(null); }

        return (
          <div>
            <header>
              <h1>Social Mini</h1>
              <div className="flex">
                {me ? (
                  <>
                    <div className="small">Signed in as <strong>{me.displayName}</strong></div>
                    <button className="btn ghost" onClick={onLogout}>Logout</button>
                  </>
                ) : (
                  <AuthForms onLogin={onLogin} />
                )}
              </div>
            </header>

            <CreatePost token={token} onCreated={(p)=>setPosts(prev=>[p,...prev])} />

            {loading ? <p className="small">Loading feed...</p> : null}

            <div className="feed">
              {posts.map(post => (
                <PostCard key={post._id} post={post} token={token} currentUser={me} onUpdated={(u)=>setPosts(prev=>prev.map(p=>p._id===u._id?u:p))} onDeleted={(id)=>setPosts(prev=>prev.filter(p=>p._id!==id))} />
              ))}
            </div>
          </div>
        );
      }

      function AuthForms({ onLogin }){
        const [mode, setMode] = useState('login');
        const [username, setUsername] = useState('');
        const [password, setPassword] = useState('');
        const [displayName, setDisplayName] = useState('');
        const [err, setErr] = useState(null);

        async function submit(e){
          e.preventDefault(); setErr(null);
          try{
            const path = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
            const body = mode === 'login' ? { username, password } : { username, password, displayName };
            const res = await api(path, 'POST', body);
            if(res.error) return setErr(res.error);
            onLogin(res.token, res.user);
            setUsername(''); setPassword(''); setDisplayName('');
          }catch(e){ setErr('request failed'); }
        }

        return (
          <form onSubmit={submit} style={{display:'flex', gap:8, alignItems:'center'}}>
            {mode === 'register' && <input placeholder="Display name" value={displayName} onChange={e=>setDisplayName(e.target.value)} />}
            <input placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} />
            <input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
            <button className="btn primary" type="submit">{mode==='login'?'Login':'Register'}</button>
            <button type="button" className="btn ghost" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Switch to Register':'Switch to Login'}</button>
            {err && <div style={{color:'red'}}>{err}</div>}
          </form>
        );
      }

      function CreatePost({ token, onCreated }){
        const [text, setText] = useState('');
        const [file, setFile] = useState(null);
        async function submit(e){
          e.preventDefault();
          if(!token) return alert('Login to create posts');
          const fd = new FormData();
          fd.append('text', text);
          if(file) fd.append('image', file);
          const res = await api('/api/posts', 'POST', fd, token, true);
          if(res.error) return alert(res.error);
          onCreated(res);
          setText(''); setFile(null);
        }
        return (
          <form onSubmit={submit} style={{margin:'12px 0'}}>
            <div className="form-row"><input type="text" placeholder="What's happening?" value={text} onChange={e=>setText(e.target.value)} /></div>
            <div className="form-row"><input type="file" onChange={e=>setFile(e.target.files[0])} /></div>
            <div className="form-row"><button className="btn primary" type="submit">Post</button></div>
          </form>
        );
      }

      function PostCard({ post, token, currentUser, onUpdated, onDeleted }){
        const [comments, setComments] = useState([]);
        const [showComments, setShowComments] = useState(false);

        useEffect(()=>{ if(showComments) loadComments(); }, [showComments]);
        async function loadComments(){ const res = await api(`/api/posts/${post._id}/comments`); setComments(res || []); }

        async function like(){ if(!token) return alert('Login to like'); const res = await api(`/api/posts/${post._id}/like`, 'POST', null, token); if(res.error) return alert(res.error); // naive refresh
          const refreshed = await api('/api/posts'); const updated = refreshed.find(p=>p._id===post._id); onUpdated(updated || post); }
        async function unlike(){ if(!token) return alert('Login to unlike'); const res = await api(`/api/posts/${post._id}/unlike`, 'POST', null, token); if(res.error) return alert(res.error); const refreshed = await api('/api/posts'); const updated = refreshed.find(p=>p._id===post._id); onUpdated(updated || post); }

        async function remove(){ if(!confirm('Delete post?')) return; const res = await api(`/api/posts/${post._id}`, 'DELETE', null, token); if(res.error) return alert(res.error); onDeleted(post._id); }
        async function edit(){ const newText = prompt('New text', post.text || ''); if(newText===null) return; const fd = new FormData(); fd.append('text', newText); const res = await api(`/api/posts/${post._id}`, 'PUT', fd, token, true); if(res.error) return alert(res.error); onUpdated(res); }

        return (
          <div className="post">
            <div style={{display:'flex', justifyContent:'space-between'}}>
              <div><strong>{post.author.displayName || post.author.username}</strong> <div className="small">{new Date(post.createdAt).toLocaleString()}</div></div>
              <div>
                {currentUser && post.author && currentUser.id === post.author._id && (
                  <>
                    <button className="btn" onClick={edit}>Edit</button>
                    <button className="btn" onClick={remove}>Delete</button>
                  </>
                )}
              </div>
            </div>
            <p>{post.text}</p>
            {post.imageUrl && <img className="post-img" src={post.imageUrl} alt="post image" />}
            <div style={{marginTop:8}}>
              <button className="btn ghost" onClick={()=>setShowComments(s=>!s)}>{showComments? 'Hide Comments':'Show Comments'}</button>
              <button className="btn" onClick={like}>Like</button>
              <button className="btn" onClick={unlike}>Unlike</button>
              <span style={{marginLeft:8}} className="small">Likes: {post.likes ? post.likes.length : 0}</span>
            </div>

            {showComments && (
              <div style={{marginTop:8}}>
                <CommentForm postId={post._id} token={token} onAdded={(c)=>setComments(prev=>[...prev, c])} />
                {comments.map(c=> (
                  <div key={c._id} className="small"><strong>{c.author.displayName || c.author.username}</strong>: {c.text} <div className="small">{new Date(c.createdAt).toLocaleString()}</div></div>
                ))}
              </div>
            )}
          </div>
        );
      }

      function CommentForm({ postId, token, onAdded }){
        const [text, setText] = useState('');
        async function submit(e){ e.preventDefault(); if(!token) return alert('Login to comment'); const res = await api(`/api/posts/${postId}/comments`, 'POST', { text }, token); if(res.error) return alert(res.error); setText(''); onAdded(res); }
        return (
          <form onSubmit={submit} style={{display:'flex', gap:8, marginBottom:8}}>
            <input type="text" placeholder="Write a comment..." value={text} onChange={e=>setText(e.target.value)} />
            <button className="btn" type="submit">Comment</button>
          </form>
        );
      }

      ReactDOM.createRoot(document.getElementById('root')).render(<App />);
    </script>
  </body>
</html>`);
});

// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
